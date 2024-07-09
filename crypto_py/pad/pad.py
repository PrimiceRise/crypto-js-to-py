# -*- coding: utf-8 -*-
# -------------------------------

# @IDE：PyCharm
# @Python：3.1x
# @Project：crypto-js-to-py

# -------------------------------

# @fileName：_pad.py
# @createTime：2024/7/3 9:50
# @author：Primice

# -------------------------------


def Pkcs7(_data: bytes | list, _unpad: bool = False, block_size: int = 16) -> list | bytes:
    if _unpad:
        return _data[:-_data[-1]]

    padding_length = block_size - len(_data) % block_size
    if isinstance(_data, list):
        return _data + [padding_length] * padding_length
    return _data + bytes([padding_length] * padding_length)

def NoPadding(_data: bytes | list, _unpad: bool = False, block_size: int = 16) -> list | bytes:
    if _unpad:
        if isinstance(_data, list):
            return _data[:_data.index(0)]
        return _data.rstrip('\0')

    padding_length = block_size - len(_data) % block_size

    if isinstance(_data, list):
        return _data + [0] * padding_length
    return _data + (padding_length) * b'\0'
