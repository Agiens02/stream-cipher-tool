import base64
import hashlib



class RC4:
    def __init__(self, public_key=None):
        self.public_key = public_key or 'none_public_key'

    def encrypt(self, string):
        """
        加密
        :param string: 输入utf-8
        :return:
        """
        bData = [ord(i) for i in string]
        result = self.__docrypt(bData)
        result = base64.b64encode(result.encode())  # 编码成可见的字符
        return str(result, encoding='utf-8')

    def decrypt(self, string):
        """
        解密
        :param string:输入utf-8
        :return:
        """
        message = base64.b64decode(string).decode()
        bData = [ord(i) for i in message]
        deresult = self.__docrypt(bData)
        return deresult

    def __rc4_init(self, K):
        """
        :param K: 密钥
        :return:
        """
        j = 0
        K = hashlib.md5(K.encode()).hexdigest()
        k = []
        SBox = []
        for i in range(256):
            SBox.append(i)
            k.append(K[i % len(K)])
        for i in range(256):
            j = (j + SBox[i] + ord(k[i])) % 256
            SBox[i], SBox[j] = SBox[j], SBox[i]

        return SBox

    def __docrypt(self, string):
        i = j = 0
        result = ''
        SBox = self.__rc4_init(self.public_key)
        for _str in string:
            i = (i + 1) % 256
            j = (j + SBox[i]) % 256
            SBox[i], SBox[j] = SBox[j], SBox[i]
            k = chr(_str ^ SBox[(SBox[i] + SBox[j]) % 256])
            result += k
        return result


if __name__ == '__main__':
    # key = generate_key(0)
    key = 'testkey'
    print(key)
    _rc4 = RC4(key)
    # print(_rc4.public_key)
    tempcode = _rc4.encrypt('就随你去天堂')
    print(tempcode)
    tempdecode = _rc4.decrypt(tempcode)
    print(tempdecode)
