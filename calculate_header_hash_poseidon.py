# pip install starknet-pathfinder-crypto   # (fast; optional)
# or: pip install cairo-lang                # (slow fallback provides poseidon in Python)

from typing import Iterable

# Choose a Poseidon backend (fast Rust one first, Cairo's Python fallback otherwise)
try:
    from starknet_pathfinder_crypto import poseidon_hash_many  # type: ignore
except Exception:
    # Fallback to cairo-lang's pure-Python Poseidon
    from starkware.cairo.common.poseidon_hash import poseidon_hash_many  # type: ignore


def _bytes_to_felts_le31(data: bytes) -> list[int]:
    """
    Pack bytes into 31-byte little-endian limbs (each < 2^248 < p), suitable for StarkNet Poseidon.
    """
    CHUNK = 31
    felts: list[int] = []
    for i in range(0, len(data), CHUNK):
        chunk = data[i : i + CHUNK]
        felts.append(int.from_bytes(chunk, "little"))
    return felts


def poseidon_hash_rlp_block_header(rlp_hex: str, return_hex: bool = False) -> int | str:
    """
    Poseidon-hash an RLP-encoded Ethereum block header (provided as 0x… hex).
    Uses StarkNet Poseidon parameters (t=3 sponge; rate=2) via poseidon_hash_many.

    Args:
        rlp_hex: str like '0x…' or plain hex without prefix.
        return_hex: if True, returns '0x…' string; otherwise returns int.

    Returns:
        int or hex string of the Poseidon hash (mod StarkNet field prime).
    """
    h = rlp_hex[2:] if rlp_hex.startswith("0x") else rlp_hex
    data = bytes.fromhex(h)
    felts = _bytes_to_felts_le31(data)
    digest_int = poseidon_hash_many(felts)
    return hex(digest_int) if return_hex else digest_int


if __name__ == "__main__":
    rlp_header = "0xf90264a0c57804b34e5105872adbdfaa5a285777fb0dda021f8e8beb70a44a549fc43ef3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479413cb6ae34a13a0977f4d7101ebc24b87bb23f0d5a0fe819d31e7693e5e352d4eb1dc7f9114449d8ae8a0011f34fb9d96e454e67161a0dbad2205d44d99e52844079c55cb1c9564a78dc9a500fe1687cf1dbc3a20f353a00e2ec5f892e31a89832a7b25e51c49acb4ceeef25d06c6d3e453cf380cbe8ed6b901000360080540084160c00c1c5ba6888c8484224b5a6013d2662308a5b4eeaa2498686030c0a4a400b280611b6e54242a367143a011aecc6841560b1082933998aa61a4c0a8a900184a802d206919b7996ea54cc507c40082dc1450dbb2c0e0a15029782c0662503252026ca09204a448750cc3306069260c0782298d91418817982a64a36e4998e845220090093934a122fe02818d17a9720e1f44da2906001930129f60d2958250068300c2ce20a12d1f47eea37258121626a561110430124a7021075d76c1830a0000620b251aa22529fcf08581b211e9e3f431d505b641e131011041184de0104e8df9d0394811424d5012322309d30047b34f11034c186a138083752cbd840225510083ec72458467a9e5d89f496c6c756d696e61746520446d6f63726174697a6520447374726962757465a0b5cccbcb9aa30b4e110f8a774e7bd1fc2b9c7f1ea424df54e79c6bd3d7a117f4880000000000000000850c272acf90a0dc21a6b5aa288c48290577ac7bea1008bec662f3ba85df55ce64e3ea1993d9878080a02821ab363ba90d64ee451979c2664821e59df3349ba53d4f53cf83eeb59c6b47"
    print(poseidon_hash_rlp_block_header(rlp_header, return_hex=True))
