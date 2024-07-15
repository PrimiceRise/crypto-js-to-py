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

from crypto_py import CryptoPY as CryptoJS
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
from crypto_py.models._options import Options

# res = SMPY.SM4.encrypt('123123','Wwcd@2016@0309#!',Options(
#     # iv='Wwcd@2016@03VI#!',
#     mode=SMPY.mode.ECB,
#     padding=SMPY.pad.Pkcs7
# ))
res = SMPY.SM4.encrypt('哈哈 鬼剑士听我号令，砍','Wwcd@2016@0309#!','CBC','Pkcs7','Wwcd@2016@03VI#!')

print(res.decode())
print(res.decode() == "pA2jnet+j76kbwIvwNu9yw==")
# print(res.decode() == "sBp0G8n72eOVDqmVVNbdpw==")

res = SMPY.SM4.decrypt("8FTkO30gKrgND5D+L+tfIafM71K33Lqp66xxiUTEUmV55GimJVFqS9bPplvykITs",'Wwcd@2016@0309#!',Options(
    iv='Wwcd@2016@03VI#!',
    mode=SMPY.mode.CBC,
    padding=SMPY.pad.Pkcs7
))
print(res.decode())