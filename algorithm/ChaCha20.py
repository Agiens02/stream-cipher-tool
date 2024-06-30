import struct


class ChaCha20:
    def __init__(self, key, nonce=b"0123456789ab"):
        if len(key) not in (16, 32):
            raise ValueError("Key length must be 128 bits (16 bytes) or 256 bits (32 bytes)")
        if len(nonce) != 12:
            raise ValueError("Nonce length must be 96 bits (12 bytes)")

        self.state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            struct.unpack('<I', key[0:4])[0],
            struct.unpack('<I', key[4:8])[0],
            struct.unpack('<I', key[8:12])[0],
            struct.unpack('<I', key[12:16])[0],
            len(key) == 32 and struct.unpack('<I', key[16:20])[0] or 0,
            len(key) == 32 and struct.unpack('<I', key[20:24])[0] or 0,
            len(key) == 32 and struct.unpack('<I', key[24:28])[0] or 0,
            len(key) == 32 and struct.unpack('<I', key[28:32])[0] or 0,
            0,
            struct.unpack('<I', nonce[0:4])[0],
            struct.unpack('<I', nonce[4:8])[0],
            struct.unpack('<I', nonce[8:12])[0],
        ]
        self.original_state = list(self.state)

    def _quarter_round(self, a, b, c, d):
        state = self.state
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] = state[d] ^ state[a]
        state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xffffffff
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] = state[b] ^ state[c]
        state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xffffffff
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] = state[d] ^ state[a]
        state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xffffffff
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] = state[b] ^ state[c]
        state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xffffffff

    def _chacha_block(self):
        state = self.state[:]
        for _ in range(10):
            self._quarter_round(0, 4, 8, 12)
            self._quarter_round(1, 5, 9, 13)
            self._quarter_round(2, 6, 10, 14)
            self._quarter_round(3, 7, 11, 15)
            self._quarter_round(0, 5, 10, 15)
            self._quarter_round(1, 6, 11, 12)
            self._quarter_round(2, 7, 8, 13)
            self._quarter_round(3, 4, 9, 14)
        for i in range(16):
            state[i] = (state[i] + self.state[i]) & 0xffffffff
        return struct.pack('<16I', *state)

    def encrypt(self, plaintext):
        ciphertext = b""
        block_counter = 1
        # plaintext=plaintext.encode('utf-8')
        while plaintext:
            self.state[12] = block_counter
            self.state = self.original_state[:]
            encrypted_block = self._chacha_block()
            keystream = encrypted_block[:len(plaintext)]
            ciphertext += bytes([plain ^ key for plain, key in zip(plaintext, keystream)])
            plaintext = plaintext[len(keystream):]
            block_counter += 1
        return ciphertext

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext).decode('utf-8')  # ChaCha20 encryption and decryption are symmetric


if __name__ == '__main__':
    key = bytes.fromhex("9dabdcb5b6a4d22326853e354b128959ab8db0300b5e3b9a2c50afa1365f77b0")
    nonce = b"0123456789ab"
    chacha = ChaCha20(key, nonce)

    plaintext = "你好，世界！"
    encrypted = chacha.encrypt(plaintext.encode('utf-8'))
    print("Encrypted:", encrypted.hex())

    decrypted = chacha.decrypt(encrypted)
    print("Decrypted:", decrypted)
