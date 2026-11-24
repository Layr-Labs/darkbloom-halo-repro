# Serve a downloaded model on AMD Halo

Catalog mode uses one signed Node OS image and one active model per boot. The
owner downloads or selects a model in AMD OS, then reboots into Darkbloom.

## Build and install the catalog-enabled OS

Follow the [text build](../../nodeos/text/README.md) with these settings. The
public key is the model publisher's Ed25519 public key in PEM format. Keep its
private key on the trusted signing workstation.

```bash
export MODEL_MODE=catalog
export MODEL_PUBLIC_KEY=/absolute/path/model-publisher.pub.pem
unset TEXT_MODEL TEXT_MODEL_ID TEXT_MODEL_SHA256

bash nodeos/text/build.sh prepare
bash nodeos/text/build.sh rootfs
bash nodeos/text/build.sh initrd
ID=halo-text-catalog-001 bash nodeos/text/build.sh options
bash nodeos/text/build.sh uki
```

Sign the UKI and install it with the [protected installer](README.md). Stage
`root.erofs`, `root.verity`, `signed.efi`, both checksum files, and `install-id`
under the bundle's `out/` directory. Pass `--model-mode catalog` to
`make-bundle.py`. The signed command line pins the OS verity root, and that
verified OS contains the model publisher's public key. Existing pinned-model
bundles continue to use the original eight-file format. A catalog-enabled
installation needs the updated protected controller and installer.

## Publish and approve a model

On the trusted model builder, place the reviewed GGUF at `text/model.gguf`
inside its own read-only EROFS image. Build a SHA-256 verity tree with 4096-byte
data and hash blocks and verify the pair against the reported root hash. The
`model-image` build target performs these steps on the Halo's Linux build host
when given `TEXT_MODEL` and a dedicated `NODEOS_TEXT_WORK` directory. Copy only
`model.erofs` and `model.verity` into the package directory and record
`model.roothash` from its `out/` directory. Use the staged
`models-stage/text/model.gguf` as the signing command's `--weights` input.
The equivalent Linux commands are below.

```bash
mkdir -p "$MODEL_SOURCE/text" "$MODEL_PACKAGE"
cp -- "$REVIEWED_GGUF" "$MODEL_SOURCE/text/model.gguf"
chmod 0755 "$MODEL_SOURCE" "$MODEL_SOURCE/text"
chmod 0644 "$MODEL_SOURCE/text/model.gguf"
mkfs.erofs --all-root "$MODEL_PACKAGE/model.erofs" "$MODEL_SOURCE"
veritysetup format --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
  "$MODEL_PACKAGE/model.erofs" "$MODEL_PACKAGE/model.verity"
veritysetup verify "$MODEL_PACKAGE/model.erofs" "$MODEL_PACKAGE/model.verity" \
  "$REVIEWED_VERITY_ROOT"
```

Use the root hash printed by `veritysetup format` for
`REVIEWED_VERITY_ROOT`. The directory must contain only the package's target
files. Publish the four files `model.erofs`, `model.verity`, `manifest.json`,
and `manifest.sig` over HTTPS. Create the manifest and signature on the trusted
signing workstation:

```bash
python3 tools/halo-e2e/model-package.py create \
  --package "$MODEL_PACKAGE" --weights "$REVIEWED_GGUF" \
  --workflow nodeos/text/workflow.json --model-id "$MODEL_ID" \
  --engine-version "$REVIEWED_LLAMA_PACKAGE_VERSION" \
  --verity-root "$REVIEWED_VERITY_ROOT" --security-version "$MODEL_SVN" \
  --private-key "$MODEL_PUBLISHER_PRIVATE_KEY"
```

Use the exact `llama.cpp-tools` package version from the serving OS build. The
signed package binds the model ID, weight digest, workflow, engine version,
security version, and verity root. The owner needs only the public key.

Use the [coordinator release procedure](../../RUNBOOK.md) with the same signed
UKI and reference boot measurements. When building the model's runtime
template, supply `-text-model-manifest "$MODEL_PACKAGE/manifest.json"`
alongside the usual `-text-model`, `-text-model-id` and `-text-workflow` flags.
Build the production coordinator approval from that template. Give each
approved package a distinct release version and choose the release SVN using
the coordinator's rollout policy. A signed model package and a signed
coordinator approval are both required for encrypted serving.

## Install or switch models in AMD OS

Run the model-package tool as the ordinary owner with Python's
`cryptography` package installed. The catalog serving image reads the library
at `$HOME/.local/share/darkbloom/models` on the same main filesystem used by the
text demo. Use the model publisher's public key from a trusted source.

```bash
library="$HOME/.local/share/darkbloom/models"
package_digest=$(python3 tools/halo-e2e/model-package.py download \
  --url "${APPROVED_HTTPS_DIRECTORY%/}/" --library "$library" \
  --public-key "$MODEL_PUBLISHER_PUBLIC_KEY")
python3 tools/halo-e2e/model-package.py select \
  --digest "$package_digest" --library "$library" \
  --public-key "$MODEL_PUBLISHER_PUBLIC_KEY"
```

If the four package files are already local, use `stage --package DIR` with
the same library and key, then select the digest it prints. The digest is the
SHA-256 of the signed `manifest.json`. Darkbloom reads the
selection at startup, verifies it again with its built-in key, and exposes the
model only through the verified mount. The TPM quote binds the report of the
exact model and package. The coordinator checks that report against the
approved OS and model pair. To withdraw a package, remove its matching approval
from the coordinator's active release set and restart the demo coordinator.

The physical acceptance test is to boot the same catalog UKI with two
different approved packages in succession and request encrypted text from
each. Also verify that corrupt weights or tree data, a modified signature, and
a valid package whose coordinator approval has been withdrawn all fail to
serve.
