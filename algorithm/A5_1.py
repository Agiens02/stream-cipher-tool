import base64


class A5_1:
    def __init__(self):
        self.R1 = [0] * 19
        self.R2 = [0] * 22
        self.R3 = [0] * 23

    def initialize_registers(self, key):
        if isinstance(key, str):
            key = int(key, 16)
        if not isinstance(key, int):
            raise TypeError("密钥必须为整数或十六进制字符串")

        self.R1 = [0] * 19
        self.R2 = [0] * 22
        self.R3 = [0] * 23
        for i in range(64):
            bit = (key >> i) & 1
            self.R1[i % 19] ^= bit
            self.R2[i % 22] ^= bit
            self.R3[i % 23] ^= bit

    def _majority(self, x, y, z):
        return (x & y) | (x & z) | (y & z)

    def _clock_register(self, reg, taps):
        feedback = 0
        for t in taps:
            feedback ^= reg[t]
        reg.pop()
        reg.insert(0, feedback)

    def _clock(self):
        majority_bit = self._majority(self.R1[8], self.R2[10], self.R3[10])
        if self.R1[8] == majority_bit:
            self._clock_register(self.R1, [13, 16, 17, 18])
        if self.R2[10] == majority_bit:
            self._clock_register(self.R2, [20, 21])
        if self.R3[10] == majority_bit:
            self._clock_register(self.R3, [7, 20, 21, 22])

    def _generate_keystream(self, length):
        keystream = []
        for _ in range(length):
            self._clock()
            keystream_bit = self.R1[-1] ^ self.R2[-1] ^ self.R3[-1]
            keystream.append(keystream_bit)
        return keystream

    def encrypt(self, plaintext, key):
        self.initialize_registers(key)
        plaintext_bits = [int(bit) for bit in
                          bin(int.from_bytes(plaintext.encode(), 'big'))[2:].zfill(len(plaintext) * 8)]
        keystream = self._generate_keystream(len(plaintext_bits))
        ciphertext_bits = [(p ^ k) for p, k in zip(plaintext_bits, keystream)]
        ciphertext = int(''.join(map(str, ciphertext_bits)), 2).to_bytes((len(ciphertext_bits) + 7) // 8, 'big')
        ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        return ciphertext

    def decrypt(self, ciphertext, key):
        self.initialize_registers(key)
        ciphertext = base64.b64decode(ciphertext)
        ciphertext_bits = [int(bit) for bit in bin(int.from_bytes(ciphertext, 'big'))[2:].zfill(len(ciphertext) * 8)]
        keystream = self._generate_keystream(len(ciphertext_bits))
        plaintext_bits = [(c ^ k) for c, k in zip(ciphertext_bits, keystream)]
        plaintext = int(''.join(map(str, plaintext_bits)), 2).to_bytes((len(plaintext_bits) + 7) // 8, 'big')
        try:
            return plaintext.decode()
        except UnicodeDecodeError:
            return plaintext


if __name__ == '__main__':

    # 示例使用
    key = 0xd8464f9189095236  # 64位密钥
    # key = generate_key(1)
    a5_1 = A5_1()

    plaintext = "你好，世界！"
    ciphertext = a5_1.encrypt(plaintext, key)
    decrypted_text = a5_1.decrypt(ciphertext, key)
    if isinstance(decrypted_text, bytes):
        print(f"Decrypted Bytes: {decrypted_text}")
    else:
        print(f"Decrypted Text: {decrypted_text}")
