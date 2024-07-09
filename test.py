# -*- coding: utf-8 -*-
# -------------------------------

# @IDE：PyCharm
# @Python：3.12
# @Project：DP

# -------------------------------

# @fileName：test.py
# @createTime：2024/7/3 10:12
# @author：Primice

# -------------------------------

# from crypto_py import CryptoPY as CryptoJS
#
# key = CryptoJS.enc.Utf8.parse("1234567890123456")
# iv = CryptoJS.enc.Utf8.parse("1234567890123456")
# data = "我是帅哥"
#
# encrypt = CryptoJS.AES.encrypt(data,key,{
#     "iv": iv,
#     "mode":CryptoJS.mode.CBC,
#     "padding":CryptoJS.pad.Pkcs7
# })
#
# print(encrypt.decode())


from crypto_py import SMPY
from crypto_py.models._sm4_options import SM4Options

# res = SMPY.SM4.encrypt('123123','Wwcd@2016@0309#!',SM4Options(
#     iv='Wwcd@2016@03VI#!',
#     mode=SMPY.mode.CBC,
#     padding=SMPY.pad.Pkcs7
# ))
res = SMPY.SM4.encrypt('123123','Wwcd@2016@0309#!','CBC','Pkcs7','Wwcd@2016@03VI#!')

print(res.decode())