# AMD Pluton EK issuing CAs

Public AMD certificates needed to verify a Strix Halo Pluton endorsement-key
(EK) chain offline.

| File | Subject | Source | SHA-256 |
|---|---|---|---|
| `amd-pluton-global-factory-ica.pem` | AMD Pluton Global Factory ICA (issuer: AMD Root CA R4) | `https://ftpm.amd.com/hsp/ica/AMD-Pluton-Global-Factory-ICA.crt` | `59:3A:17:94:F9:E1:74:76:C7:AD:42:7D:29:08:A9:7C:45:14:51:C9:E0:93:9F:DC:80:D5:D6:62:C2:32:D4:01` |
| `amd-pluton-00b70f00-non-fips-ek-ica.pem` | AMD Pluton Per-Product Factory NON-FIPS EK ICA DFID00B70F00 | `https://ftpm.amd.com/hsp/ica/00B70F00-non-fips.crt` | `08:DD:2C:92:FA:16:BC:E6:5C:FD:19:84:B6:A5:39:1A:E8:1C:E2:66:62:5D:AF:D7:1B:66:55:BC:EE:00:16:86` |

The Global Factory ICA is the **trust anchor**: its issuer, "AMD Root CA R4",
carries no download location and was not found published. Verifiers pin the
Global Factory ICA by the SHA-256 above
(`poc-rs/crates/tpmattest/src/ekchain.rs`, `PLUTON_GLOBAL_FACTORY_ICA_SHA256`).

The two lower links of the chain (the per-chip "DEVICE EKICA" and the
"PLUTON Firmware SVNxx" ICA) live in the TPM's NV storage and are read with
`tools/tpm/read_ek_chain.py`. They and the EK certificates are device-unique,
so they are not stored in this repository.
