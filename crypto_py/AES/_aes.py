# -*- coding: utf-8 -*-
# -------------------------------

# @IDE：PyCharm
# @Python：3.1x
# @Project：DP

# -------------------------------

# @fileName：_aes.py
# @createTime：2024/7/3 9:51
# @author：Primice

# -------------------------------
from Cryptodome.Cipher import AES as aes

from ..models._aes_options import AESOption
from ..models._decrypt_data import DecryptData
from ..models._encrypt_data import EncryptData
from ..enc.enc import Utf8




class AES:
    @staticmethod
    def encrypt(data: str, key: bytes, options: AESOption|dict) -> EncryptData:

        data = Utf8.parse(data)
        if isinstance(options,dict):
            options = AESOption(**options)
        match options.mode:
            case aes.MODE_ECB:
                cipher = aes.new(key=key, mode=options.mode)
                padded_data = options.padding(data)
                # padded_data = data.encode('utf-8') + (16 - len(data.encode('utf-8')) % 16) * b'\0'
                encrypted_data = cipher.encrypt(padded_data)
                return EncryptData(encrypted_data)
            case aes.MODE_CBC:
                cipher = aes.new(key=key, mode=options.mode, iv=options.iv)
                padded_data = options.padding(data)
                # padded_data = data.encode('utf-8') + (16 - len(data.encode('utf-8')) % 16) * b'\0'
                encrypted_data = cipher.encrypt(padded_data)
                return EncryptData(encrypted_data)

    @staticmethod
    def decrypt(data: str, key: bytes, options: AESOption) -> DecryptData:
        match options.mode:
            case aes.MODE_ECB:
                cipher = aes.new(key, options.mode)
                return DecryptData(cipher, data, options.padding)
            case aes.MODE_CBC:
                cipher = aes.new(key, options.mode, iv=options.iv)
                return DecryptData(cipher, data, options.padding)

