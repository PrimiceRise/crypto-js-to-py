# -*- coding: utf-8 -*-
# -------------------------------

# @IDE：PyCharm
# @Python：3.1x
# @Project：DP

# -------------------------------

# @fileName：_encrypt_data.py
# @createTime：2024/7/3 9:56
# @author：Primice

# -------------------------------
import binascii
import base64

class EncryptData:
    def __init__(self, encrypted_data):
        self.encrypted_data = encrypted_data

    def decode(self) -> str:
        return str(base64.encodebytes(self.encrypted_data), encoding='utf-8').replace('\n', '')

    @property
    def ciphertext(self) -> bytes:
        return binascii.hexlify(self.encrypted_data)

    def __str__(self) -> str:
        return f"<class EncryptData data:'{self.encrypted_data}'>"