import hashlib
import base58
from typing import List
# Define the correct Signet's tpub version prefix (BIP32 standard for testnet & signet)
signet_tpub_prefix = bytes.fromhex("043587CF")


def base58_encode(data: bytes) -> str:
    return base58.b58encode(data).decode()

#146843229b3ffb043bf8da7b12baf0f80d883632380342424efcfcfcfcfcfcfc
# Given public key (uncompressed, 32 bytes)
public_key = bytes.fromhex(
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

# Constructing a proper BIP32 extended public key (tpub)
depth = bytes.fromhex("00")  # Depth: 0 (master key)
parent_fingerprint = bytes.fromhex(
    "00000000")  # Parent fingerprint: 0 (no parent)
child_number = bytes.fromhex("00000000")  # Child number: 0 (master key)
chain_code = hashlib.sha256(
    public_key).digest()[:32]  # Generate a pseudo chain code

# Construct a compressed public key (33 bytes) by prepending 0x02 (even Y-coord assumed)
compressed_pubkey = b'\x02' + public_key[:32]

# Construct full BIP32 extended key payload
bip32_payload = (signet_tpub_prefix + depth + parent_fingerprint +
                 child_number + chain_code + compressed_pubkey)

# Compute checksum (first 4 bytes of double SHA256)
checksum = hashlib.sha256(hashlib.sha256(bip32_payload).digest()).digest()[:4]

# Perform Base58Check encoding
tpub_final_corrected = base58_encode(bip32_payload + checksum)

print(tpub_final_corrected)
print(chain_code)
