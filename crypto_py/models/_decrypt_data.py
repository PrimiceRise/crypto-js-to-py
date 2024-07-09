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
from typing import Callable
import base64
import binascii

from ..enc.enc import Utf8


class DecryptData:
    def __init__(self, _cipher: AES, data: str, _padding: Callable):
        self._data = data
        self._padding = _padding
        self.__cipher = _cipher

    def decode(self) -> bytes:
        data = Utf8.parse(self._data)
        decrypted_data = self.__cipher.decrypt(base64.decodebytes(data))
        return self._padding(decrypted_data, True).decode()

    @property
    def ciphertext(self) -> bytes:
        decrypted_data = self.__cipher.decrypt(binascii.unhexlify(self._data))
        return self._padding(decrypted_data, True)

    def __str__(self) -> str:
        return f"<class DecryptData data:'{self._data}'>"
