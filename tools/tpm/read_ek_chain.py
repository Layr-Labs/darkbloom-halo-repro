#!/usr/bin/env python3
"""Read TPM identity and the endorsement-key (EK) certificate chain from the
Halo's Pluton TPM with raw TPM2 commands (no tpm2-tools needed).

    sudo python3 read_ek_chain.py <out-dir>

Prints the manufacturer, firmware version, active PCR banks and NV indices,
and writes the EK certificates and the on-chip issuing CAs as DER files.
The EK certificates identify this specific chip: keep them out of git.
"""
import os
import struct
import sys

TPM_DEVICE = "/dev/tpmrm0"
TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS = 0x8001, 0x8002
TPM_CC_GET_CAPABILITY, TPM_CC_NV_READ_PUBLIC, TPM_CC_NV_READ = 0x17A, 0x169, 0x14E
TPM_CAP_HANDLES, TPM_CAP_PCRS, TPM_CAP_TPM_PROPERTIES = 1, 5, 6
TPM_PT_FIXED = 0x100
TPM_PT_NV_BUFFER_MAX = 0x12C
TPM_RS_PW = 0x40000009
NV_FIRST_INDEX = 0x01000000
# TCG EK credential profile indices plus Pluton's chain indices.
NV_CERTIFICATES = {
    0x01C00002: "ek-rsa.der",
    0x01C0000A: "ek-ecc.der",
    0x01C00100: "pluton-fw-ekica.der",
    0x01C00101: "pluton-device-ekica.der",
}
HASH_ALGORITHMS = {0x4: "sha1", 0xB: "sha256", 0xC: "sha384", 0xD: "sha512", 0x12: "sm3_256"}


class Tpm:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR)

    def command(self, code, body, tag=TPM_ST_NO_SESSIONS):
        os.write(self.fd, struct.pack(">HII", tag, 10 + len(body), code) + body)
        response = os.read(self.fd, 8192)
        response_code = struct.unpack(">I", response[6:10])[0]
        if response_code:
            raise RuntimeError(f"TPM command 0x{code:X} failed with 0x{response_code:X}")
        return response[10:]

    def capability(self, capability, first, count):
        """Return (more_data, entry_count, entries) for one GetCapability call."""
        data = self.command(TPM_CC_GET_CAPABILITY, struct.pack(">III", capability, first, count))
        return bool(data[0]), struct.unpack(">I", data[5:9])[0], data[9:]

    def fixed_properties(self):
        _, count, data = self.capability(TPM_CAP_TPM_PROPERTIES, TPM_PT_FIXED, 64)
        return dict(struct.unpack(">II", data[8 * i:8 * i + 8]) for i in range(count))

    def active_pcr_banks(self):
        _, count, data = self.capability(TPM_CAP_PCRS, 0, 16)
        banks, offset = [], 0
        for _ in range(count):
            algorithm, size = struct.unpack(">HB", data[offset:offset + 3])
            if any(data[offset + 3:offset + 3 + size]):
                banks.append(HASH_ALGORITHMS.get(algorithm, hex(algorithm)))
            offset += 3 + size
        return banks

    def nv_indices(self):
        indices, first = [], NV_FIRST_INDEX
        while True:
            more, count, data = self.capability(TPM_CAP_HANDLES, first, 128)
            batch = [struct.unpack(">I", data[4 * i:4 * i + 4])[0] for i in range(count)]
            indices += [handle for handle in batch if handle >> 24 == NV_FIRST_INDEX >> 24]
            if not more or not batch:
                return indices
            first = batch[-1] + 1

    def nv_read(self, index, max_chunk):
        public = self.command(TPM_CC_NV_READ_PUBLIC, struct.pack(">I", index))
        policy_size = struct.unpack(">H", public[12:14])[0]
        size = struct.unpack(">H", public[14 + policy_size:16 + policy_size])[0]
        password_session = struct.pack(">IHBH", TPM_RS_PW, 0, 0, 0)
        data = b""
        while len(data) < size:
            chunk = min(max_chunk, size - len(data))
            body = (struct.pack(">III", index, index, len(password_session)) + password_session
                    + struct.pack(">HH", chunk, len(data)))
            response = self.command(TPM_CC_NV_READ, body, TPM_ST_SESSIONS)
            length = struct.unpack(">H", response[4:6])[0]
            if length == 0:
                raise RuntimeError(f"NV index 0x{index:08X} returned no data at offset {len(data)}")
            data += response[6:6 + length]
        return data


def ascii_property(properties, *keys):
    return b"".join(properties.get(key, 0).to_bytes(4, "big") for key in keys).rstrip(b"\0").decode(errors="replace")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    tpm = Tpm(TPM_DEVICE)

    properties = tpm.fixed_properties()
    firmware = (properties.get(0x10B, 0) >> 16, properties.get(0x10B, 0) & 0xFFFF,
                properties.get(0x10C, 0) >> 16, properties.get(0x10C, 0) & 0xFFFF)
    print("manufacturer:", ascii_property(properties, 0x105))
    print("vendor:", ascii_property(properties, 0x106, 0x107, 0x108, 0x109))
    print("firmware:", ".".join(str(part) for part in firmware))
    print("active PCR banks:", ", ".join(tpm.active_pcr_banks()))
    indices = tpm.nv_indices()
    print("NV indices:", " ".join(f"{index:08x}" for index in indices))

    for index, filename in NV_CERTIFICATES.items():
        if index not in indices:
            print(f"{index:08x}: absent")
            continue
        certificate = tpm.nv_read(index, properties.get(TPM_PT_NV_BUFFER_MAX, 512))
        with open(os.path.join(out_dir, filename), "wb") as handle:
            handle.write(certificate)
        print(f"{index:08x}: {len(certificate)} bytes -> {filename}")


if __name__ == "__main__":
    main()
