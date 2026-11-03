//! Firmware, kernel and GPU state the measured OS reports in statements.
//! Everything here is readable without root on the Halo. BIOS settings are
//! not in the boot measurements on this platform (changing TSME left PCR 1
//! unchanged), so they are reported by the measured OS.

use db_tpmattest::Status;
use db_tpmattest::statement::{BOOT_HEALTH_MAX_BYTES, BootHealth};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

const EFI_GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const BOOT_HEALTH_PATH: &str = "/run/darkbloom/boot-health.json";

fn read_trim(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|b| String::from_utf8_lossy(&b).trim().to_owned())
}

/// A UEFI variable's data (without the 4-byte attributes).
fn efi_var(name: &str) -> Option<Vec<u8>> {
    let b = std::fs::read(Path::new("/sys/firmware/efi/efivars").join(name)).ok()?;
    b.get(4..).map(<[u8]>::to_vec)
}

/// Sorted directory entries whose names start with `prefix` (a tiny
/// `filepath.Glob` for `dir/prefix*`).
fn glob_dir(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok).filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with(prefix))).map(|e| e.path()).collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn base_name(p: &Path) -> String {
    p.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned()
}

/// Formats a KFD `gfx_target_version` (e.g. 110501) as `gfx1151`.
fn gfx_target(v: i64) -> String {
    format!("gfx{}{}{:x}", v / 10000, v / 100 % 100, v % 100)
}

fn read_boot_health(path: &Path, current_boot_id: &str) -> Option<BootHealth> {
    let file = std::fs::File::open(path).ok()?;
    let mut raw = Vec::new();
    file.take((BOOT_HEALTH_MAX_BYTES + 1) as u64).read_to_end(&mut raw).ok()?;
    if raw.len() > BOOT_HEALTH_MAX_BYTES {
        return None;
    }
    let report: BootHealth = serde_json::from_slice(&raw).ok()?;
    (report.boot_id == current_boot_id && report.valid()).then_some(report)
}

/// Reads firmware settings, kernel hardening and GPU state.
pub fn collect_status() -> Status {
    let mut s = Status {
        kernel_release: read_trim(Path::new("/proc/sys/kernel/osrelease")).unwrap_or_default(),
        cmdline: read_trim(Path::new("/proc/cmdline")).unwrap_or_default(),
        ..Status::default()
    };
    if let Some(l) = read_trim(Path::new("/sys/kernel/security/lockdown"))
        && let (Some(i), Some(j)) = (l.find('['), l.find(']'))
        && j > i
    {
        s.lockdown = l.get(i + 1..j).unwrap_or_default().to_owned();
    }
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        s.debugfs_mounted = mounts.lines().any(|line| line.split_whitespace().nth(2) == Some("debugfs"));
    }
    if let Some(v) = efi_var(&format!("SecureBoot-{EFI_GLOBAL}"))
        && let [b] = v.as_slice()
    {
        s.secure_boot = Some(*b == 1);
    }
    if let Some(v) = efi_var(&format!("SetupMode-{EFI_GLOBAL}"))
        && let [b] = v.as_slice()
    {
        s.setup_mode = Some(*b == 1);
    }
    // AMD DASH (hidden BIOS form; writable from any OS, so checked every boot).
    if let Some(v) = efi_var("DashSetupVar-64c1cc5f-ed4c-4042-9455-d3859b2f78d8")
        && let Some(b) = v.first()
    {
        s.dash_enabled = Some(*b != 0);
    }
    if let Some(v) = efi_var("MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23") {
        s.moklist_sha256 = hex::encode(Sha256::digest(&v));
    }
    // AMD PSP state from the ccp driver.
    let mut psp = BTreeMap::new();
    let ccp = Path::new("/sys/bus/pci/drivers/ccp");
    if let Some(dir) = glob_dir(ccp, "").into_iter().find(|d| d.join("tsme_status").exists()) {
        for k in [
            "tsme_status",
            "fused_part",
            "debug_lock_on",
            "anti_rollback_status",
            "rom_armor_enforced",
            "boot_integrity",
            "rpmc_production_enabled",
        ] {
            if let Some(v) = read_trim(&dir.join(k)) {
                psp.insert(k.to_owned(), v);
            }
        }
        if let Some(v) = psp.get("tsme_status") {
            s.tsme_active = Some(v == "1");
        }
    }
    s.psp = psp;
    if let Ok(swaps) = std::fs::read_to_string("/proc/swaps") {
        s.swap_active = swaps.trim().lines().count() > 1;
    }
    // GPU: the amdgpu device, its isolation setting and IOMMU group.
    if let Some(dev) = glob_dir(Path::new("/sys/bus/pci/drivers/amdgpu"), "0000:").into_iter().next() {
        s.gpu.pci = base_name(&dev);
        s.gpu.driver = "amdgpu".to_owned();
        if let Some(v) = read_trim(&dev.join("enforce_isolation"))
            && let Some(n) = v.split_whitespace().next().and_then(|f| f.parse().ok())
        {
            s.gpu.enforce_isolation = Some(n);
        }
        if let Ok(g) = std::fs::read_link(dev.join("iommu_group")) {
            let group = base_name(&g);
            s.gpu.iommu_type = read_trim(&Path::new("/sys/kernel/iommu_groups").join(&group).join("type")).unwrap_or_default();
            s.gpu.iommu_group = group;
        }
        if let Some(v) = read_trim(&dev.join("mem_info_gtt_total")) {
            s.gpu.gtt_bytes = v.parse().unwrap_or(0);
        }
        for node in glob_dir(Path::new("/sys/class/kfd/kfd/topology/nodes"), "") {
            let Ok(props) = std::fs::read_to_string(node.join("properties")) else { continue };
            for line in props.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if let [key, val] = f.as_slice()
                    && *key == "gfx_target_version"
                    && *val != "0"
                    && let Ok(v) = val.parse::<i64>()
                {
                    s.gpu.target = gfx_target(v);
                }
            }
        }
    }
    s.gpu.owner = "node".to_owned();
    if let Some(id) = read_trim(Path::new("/proc/sys/kernel/random/boot_id")) {
        s.boot_health = read_boot_health(Path::new(BOOT_HEALTH_PATH), &id);
    }
    s
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn gfx_names() {
        assert_eq!(gfx_target(110501), "gfx1151");
        assert_eq!(gfx_target(90010), "gfx90a");
        assert_eq!(gfx_target(110000), "gfx1100");
    }

    #[test]
    fn collect_never_panics() {
        let s = collect_status();
        assert_eq!(s.gpu.owner, "node");
    }

    #[test]
    fn boot_health_is_bounded_and_bound_to_this_boot() {
        let path = std::env::temp_dir().join(format!("darkbloom-boot-health-{}", std::process::id()));
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let report = BootHealth { v: 1, boot_id: id.to_owned(), ..BootHealth::default() };
        std::fs::write(&path, serde_json::to_vec(&report).expect("encode")).expect("write");
        assert_eq!(read_boot_health(&path, id), Some(report));
        assert!(read_boot_health(&path, "ffffffff-ffff-ffff-ffff-ffffffffffff").is_none());
        std::fs::write(&path, vec![b'x'; BOOT_HEALTH_MAX_BYTES + 1]).expect("write oversized");
        assert!(read_boot_health(&path, id).is_none());
        std::fs::remove_file(&path).expect("remove");
    }
}
