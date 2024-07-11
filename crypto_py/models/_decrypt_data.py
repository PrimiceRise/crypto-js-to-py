# -*- coding: utf-8 -*-
# -------------------------------

# @IDE：PyCharm
# @Python：3.1x
# @Project：DP

# -------------------------------

# @fileName：_decrypt_data.py
# @createTime：2024/7/3 9:56
# @author：Primice

# -------------------------------
from Cryptodome.Cipher import AES
from typing import Type
import base64
import binascii

from ..enc.enc import Utf8
from ..pad.pad import Pad


class DecryptData:
    """ AES的解密数据对象。

    实例化后的类可以通过decode()方法获取utf8解密内容
    十六进制密文也可以通过ciphertext()方法来获取hex解密内容

    example:
        cipher = AES.new(...)
        data:str = "..."
        padding = unpad(....)

        decrypter = DecryptDate(cipher,data,padding)
        print(decrypter.decode("utf-8"))
    or:
        print(decrypter.ciphertext.decode("utf-8"))

    """
    def __init__(self, cipher: AES, data: str, padding: Type[Pad]):
        """初始化函数

        @param cipher : AES实例
        @param data : 密文字符串
        @param padding : Pad子类实例 例如 Pkcs7 NoPadding

        """
        self._data = data
        self.__padding = padding
        self.__cipher = cipher

    def decode(self) -> bytes:
        data = Utf8.parse(self._data)
        decrypted_data = self.__cipher.decrypt(base64.decodebytes(data))
        return self.__padding.pad(decrypted_data).decode()

    @property
    def ciphertext(self) -> bytes:
        decrypted_data = self.__cipher.decrypt(binascii.unhexlify(self._data))
        return self.__padding.pad(decrypted_data)

    def __str__(self) -> str:
        return f"<class DecryptData data:'{self._data[:10]}'>"
