"""Implementasi block cipher edukatif buatan sendiri.

Cipher ini dibuat untuk pembelajaran akademik dan tidak ditujukan
untuk keamanan produksi.
"""

from __future__ import annotations

from app.utils import BLOCK_SIZE, rotate_left, xor_bytes


def _build_custom_sbox() -> tuple:
    """Bangun S-Box kustom berbentuk permutasi 0..255."""
    available = list(range(256))
    sbox = []
    cursor = 73
    for index in range(256):
        cursor = (cursor + 97 + rotate_left(index, 1, 8)) % len(available)
        sbox.append(available.pop(cursor))
        if available:
            cursor %= len(available)
    return tuple(sbox)


SBOX = _build_custom_sbox()
BYTE_PERMUTATION = (2, 5, 1, 7, 3, 0, 6, 4)


class AcademicBlockCipher:
    """Cipher blok 128-bit berbasis struktur Feistel sederhana."""

    BLOCK_SIZE = BLOCK_SIZE
    HALF_SIZE = BLOCK_SIZE // 2
    ROUNDS = 12
    _HALF_MASK = (1 << 64) - 1

    def __init__(self, key_material: bytes) -> None:
        if not key_material:
            raise ValueError("Key material tidak boleh kosong.")
        self._key_material = key_material
        expanded = self._expand_key_material(32 + (self.ROUNDS * self.HALF_SIZE))
        self._pre_whitening = expanded[: self.BLOCK_SIZE]
        self._post_whitening = expanded[self.BLOCK_SIZE : self.BLOCK_SIZE * 2]
        round_key_stream = expanded[self.BLOCK_SIZE * 2 :]
        self._round_keys = [
            round_key_stream[index : index + self.HALF_SIZE]
            for index in range(0, len(round_key_stream), self.HALF_SIZE)
        ]

    def _stretch_key(self, target_length: int) -> bytes:
        """Panjangkan key user menjadi state awal yang lebih kaya pola."""
        state = bytearray((0xA5 ^ (index * 37)) & 0xFF for index in range(target_length))
        for index, byte in enumerate(self._key_material):
            position = index % target_length
            state[position] ^= rotate_left(byte, index % 8, 8)
            buddy = (position * 5 + 7) % target_length
            state[buddy] = (state[buddy] + byte + index) & 0xFF
        for round_index in range(target_length * 6):
            position = round_index % target_length
            left = state[(position - 1) % target_length]
            right = state[(position + 1) % target_length]
            state[position] = SBOX[(state[position] ^ left ^ round_index) & 0xFF]
            state[position] = (
                state[position]
                + rotate_left(right, round_index % 8, 8)
                + position
                + round_index
            ) & 0xFF
        return bytes(state)

    def _expand_key_material(self, output_length: int) -> bytes:
        """Bangun stream key untuk whitening dan seluruh ronde."""
        seed = bytearray(self._stretch_key(32))
        output = bytearray()
        counter = 0
        while len(output) < output_length:
            index = counter % len(seed)
            neighbor = seed[(index + 11) % len(seed)]
            mixed = (seed[index] + rotate_left(neighbor, counter % 8, 8) + (13 * counter)) & 0xFF
            mixed ^= self._key_material[counter % len(self._key_material)]
            mixed = SBOX[mixed]
            output.append(mixed)
            seed[index] = (seed[index] ^ mixed ^ rotate_left(counter & 0xFF, index % 8, 8)) & 0xFF
            alt = (index * 7 + 3) % len(seed)
            seed[alt] = (seed[alt] + mixed + alt + counter) & 0xFF
            counter += 1
        return bytes(output)

    def _round_function(self, half_block: bytes, round_key: bytes, round_index: int) -> bytes:
        """Round function yang memadukan XOR, substitusi, permutasi, dan rotasi."""
        half_value = int.from_bytes(half_block, "big")
        key_value = int.from_bytes(round_key, "big")
        mixed = (
            half_value
            + key_value
            + ((round_index + 1) * 0x9E3779B185EBCA87)
        ) & self._HALF_MASK
        mixed ^= rotate_left(key_value, (round_index * 5 + 1) % 64, 64)
        mixed = rotate_left(mixed, (round_index * 7 + 3) % 64, 64)
        state = mixed.to_bytes(self.HALF_SIZE, "big")
        substituted = bytes(
            SBOX[(byte + round_index + offset) & 0xFF] for offset, byte in enumerate(state)
        )
        permuted = bytes(substituted[position] for position in BYTE_PERMUTATION)
        mixed_bytes = bytearray(self.HALF_SIZE)
        for index, byte in enumerate(permuted):
            partner = permuted[(index + 3) % self.HALF_SIZE]
            mixed_bytes[index] = (
                byte
                + rotate_left(partner, (round_index + index) % 8, 8)
                + ((17 * round_index) ^ (index * 11))
            ) & 0xFF
        return bytes(mixed_bytes)

    def encrypt_block(self, block: bytes) -> bytes:
        """Enkripsi tepat satu blok 16 byte."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError("encrypt_block() membutuhkan blok tepat 16 byte.")
        state = xor_bytes(block, self._pre_whitening)
        left = state[: self.HALF_SIZE]
        right = state[self.HALF_SIZE :]
        for round_index, round_key in enumerate(self._round_keys):
            left, right = right, xor_bytes(left, self._round_function(right, round_key, round_index))
        return xor_bytes(left + right, self._post_whitening)

    def decrypt_block(self, block: bytes) -> bytes:
        """Dekripsi tepat satu blok 16 byte."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError("decrypt_block() membutuhkan blok tepat 16 byte.")
        state = xor_bytes(block, self._post_whitening)
        left = state[: self.HALF_SIZE]
        right = state[self.HALF_SIZE :]
        for round_index in range(self.ROUNDS - 1, -1, -1):
            left, right = (
                xor_bytes(right, self._round_function(left, self._round_keys[round_index], round_index)),
                left,
            )
        return xor_bytes(left + right, self._pre_whitening)

