import hashlib

def sha256(data: bytes) -> bytes:
    """Compute SHA256 hash."""
    return hashlib.sha256(data).digest()

def varint_encode(value: int) -> bytes:
    """Encode an integer as Bitcoin VarInt."""
    if value < 0xfd:
        return value.to_bytes(1, "little")
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, "little")
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, "little")
    else:
        return b'\xff' + value.to_bytes(8, "little")

def tagged_hash(tag: str, msg: bytes) -> bytes:
    """Compute Bitcoin TaggedHash."""
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + msg)

def compute_leaf_hash(script_hex: str) -> str:
    """Compute the TapLeaf hash from a hex-encoded Bitcoin script."""
    script_bytes = bytes.fromhex(script_hex)
    leaf_version = b'\xc0'  # Default Leaf Version
    script_len = len(script_bytes)
    varint_len = varint_encode(script_len)
    to_hash = leaf_version + varint_len + script_bytes
    leaf_hash = tagged_hash("TapLeaf", to_hash)
    return leaf_hash.hex()

# Example usage:
script_hex = "20dc8d2f9eff0c4f4dbde070a48e330efc908b62a766568d91e658f284b324b878ad20d23c2c25e1fcf8fd1c21b9a402c19e2e309e531e45e92fb1e9805b6056b0cc76ad200aee0509b16db71c999238a4827db945526859b13c95487ab46725357c9a9f25ac20113c3a32a9d320b72190a04a020a0db3976ef36972673258e9a38a364f3dc3b0ba2017921cf156ccb4e73d428f996ed11b245313e37e27c978ac4d2cc21eca4672e4ba203bb93dfc8b61887d771f3630e9a63e97cbafcfcc78556a474df83a31a0ef899cba2040afaf47c4ffa56de86410d8e47baa2bb6f04b604f4ea24323737ddc3fe092dfba2079a71ffd71c503ef2e2f91bccfc8fcda7946f4653cef0d9f3dde20795ef3b9f0ba20d21faf78c6751a0d38e6bd8028b907ff07e9a869a43fc837d6b3f8dff6119a36ba20f5199efae3f28bb82476163a7e458c7ad445d9bffb0682d10d3bdb2cb41f8e8eba20fa9d882d45f4060bdb8042183828cd87544f1ea997380e586cab77d5fd698737ba569c"
leaf_hash = compute_leaf_hash(script_hex)
print("Leaf Hash:", leaf_hash)
