#!/usr/bin/env python3
"""Have the Pluton TPM sign a fresh boot-state quote.

    sudo python3 collect_quote.py <nonce-hex> > quote.json

Creates a transient restricted ECC P-256 signing key (an attestation key, AK)
under the endorsement hierarchy, reads the quoted SHA-256 PCRs, asks the TPM to
quote them over the verifier's nonce, and prints JSON with the AK public
area, the signed attestation structure, the signature, the PCR values and the
boot event log. Nothing persists: the key is flushed before exit.
Verify off the device with verify_quote.py.

The endorsement hierarchy matters: TPM 2.0 obfuscates resetCount,
restartCount and firmwareVersion in quotes signed by keys outside the
endorsement and platform hierarchies, and reboot detection needs them.
"""
import base64
import json
import os
import struct
import sys

TPM_DEVICE = "/dev/tpmrm0"
EVENT_LOG = "/sys/kernel/security/tpm0/binary_bios_measurements"
ST_NO_SESSIONS, ST_SESSIONS = 0x8001, 0x8002
CC_CREATE_PRIMARY, CC_QUOTE, CC_PCR_READ, CC_FLUSH_CONTEXT = 0x131, 0x158, 0x17E, 0x165
RH_ENDORSEMENT, RS_PW = 0x4000000B, 0x40000009
ALG_ECC, ALG_SHA256, ALG_NULL, ALG_ECDSA, ECC_NIST_P256 = 0x0023, 0x000B, 0x0010, 0x0018, 0x0003
# fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA | restricted | sign
AK_ATTRIBUTES = 0x2 | 0x10 | 0x20 | 0x40 | 0x400 | 0x10000 | 0x40000
QUOTED_PCRS = [0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 14]
PASSWORD_SESSION = struct.pack(">IHBH", RS_PW, 0, 0, 0)


def tpm2b(data=b""):
    return struct.pack(">H", len(data)) + data


def pcr_selection(pcrs):
    bitmap = bytearray(3)
    for pcr in pcrs:
        bitmap[pcr // 8] |= 1 << (pcr % 8)
    return struct.pack(">IHB", 1, ALG_SHA256, 3) + bytes(bitmap)


AK_TEMPLATE = (
    struct.pack(">HHI", ALG_ECC, ALG_SHA256, AK_ATTRIBUTES) + tpm2b()  # empty authPolicy
    + struct.pack(">HHHHH", ALG_NULL, ALG_ECDSA, ALG_SHA256, ECC_NIST_P256, ALG_NULL)
    + tpm2b() + tpm2b()  # unique point: empty x and y
)


class Tpm:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR)

    def command(self, code, body, sessions=False):
        tag = ST_SESSIONS if sessions else ST_NO_SESSIONS
        os.write(self.fd, struct.pack(">HII", tag, 10 + len(body), code) + body)
        response = os.read(self.fd, 8192)
        response_code = struct.unpack(">I", response[6:10])[0]
        if response_code:
            raise RuntimeError(f"TPM command 0x{code:X} failed with 0x{response_code:X}")
        return response[10:]

    def create_attestation_key(self):
        body = (struct.pack(">II", RH_ENDORSEMENT, len(PASSWORD_SESSION)) + PASSWORD_SESSION
                + tpm2b(tpm2b() + tpm2b())  # inSensitive: empty userAuth and data
                + tpm2b(AK_TEMPLATE) + tpm2b() + struct.pack(">I", 0))
        response = self.command(CC_CREATE_PRIMARY, body, sessions=True)
        handle = struct.unpack(">I", response[0:4])[0]
        public_size = struct.unpack(">H", response[8:10])[0]
        return handle, response[10:10 + public_size]

    def read_pcrs(self, pcrs):
        values, remaining = {}, list(pcrs)
        while remaining:
            response = self.command(CC_PCR_READ, pcr_selection(remaining))
            selections, offset, returned = struct.unpack(">I", response[4:8])[0], 8, []
            for _ in range(selections):
                size = response[offset + 2]
                bitmap = response[offset + 3:offset + 3 + size]
                returned += [i for i in range(size * 8) if bitmap[i // 8] >> (i % 8) & 1]
                offset += 3 + size
            digest_count = struct.unpack(">I", response[offset:offset + 4])[0]
            offset += 4
            if digest_count == 0:
                raise RuntimeError("PCR_Read returned no digests")
            for pcr in sorted(returned)[:digest_count]:
                size = struct.unpack(">H", response[offset:offset + 2])[0]
                values[pcr] = response[offset + 2:offset + 2 + size].hex()
                offset += 2 + size
            remaining = [pcr for pcr in remaining if pcr not in values]
        return values

    def quote(self, handle, nonce):
        body = (struct.pack(">II", handle, len(PASSWORD_SESSION)) + PASSWORD_SESSION
                + tpm2b(nonce) + struct.pack(">H", ALG_NULL) + pcr_selection(QUOTED_PCRS))
        response = self.command(CC_QUOTE, body, sessions=True)
        parameters_end = 4 + struct.unpack(">I", response[0:4])[0]
        attest_size = struct.unpack(">H", response[4:6])[0]
        return response[6:6 + attest_size], response[6 + attest_size:parameters_end]

    def flush(self, handle):
        self.command(CC_FLUSH_CONTEXT, struct.pack(">I", handle))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    nonce = bytes.fromhex(sys.argv[1])
    if not 16 <= len(nonce) <= 32:
        sys.exit("nonce must be 16-32 bytes")
    tpm = Tpm(TPM_DEVICE)
    handle, ak_public = tpm.create_attestation_key()
    try:
        pcrs = tpm.read_pcrs(QUOTED_PCRS)
        attest, signature = tpm.quote(handle, nonce)
    finally:
        tpm.flush(handle)
    json.dump({
        "quoted_pcrs": QUOTED_PCRS,
        "ak_public": ak_public.hex(),
        "attest": attest.hex(),
        "signature": signature.hex(),
        "pcr_read_sha256": {str(pcr): value for pcr, value in sorted(pcrs.items())},
        "event_log": base64.b64encode(open(EVENT_LOG, "rb").read()).decode(),
    }, sys.stdout)
    print()


if __name__ == "__main__":
    main()
