# -*- coding: utf-8 -*-
# -------------------------------

# @IDE：PyCharm
# @Python：3.1x
# @Project：crypto-js-to-py

# -------------------------------

# @fileName：_sm4.py
# @createTime：2024/7/5 10:05
# @author：Primice

# -------------------------------

def string_to_array(s):
    if not isinstance(s, str):
        s = str(s)
    return list(bytearray(s, 'utf-8'))


def rotate_left(x, y):
    return ((x << y) & 0xFFFFFFFF) | (x >> (32 - y))


def tau_transform(a):
    return (Sbox[(a >> 24) & 0xff] << 24 |
            Sbox[(a >> 16) & 0xff] << 16 |
            Sbox[(a >> 8) & 0xff] << 8 |
            Sbox[a & 0xff])


def encrypt_round_keys(key):
    def t_transform2(z):
        b = tau_transform(z)
        c = b ^ rotate_left(b, 13) ^ rotate_left(b, 23)
        return c

    keys = []
    mk = [
        key[0 + i * 4] << 24 | key[1 + i * 4] << 16 | key[2 + i * 4] << 8 | key[3 + i * 4]
        for i in range(4)
    ]

    k = [0] * 36
    k[0] = mk[0] ^ FK[0]
    k[1] = mk[1] ^ FK[1]
    k[2] = mk[2] ^ FK[2]
    k[3] = mk[3] ^ FK[3]

    for i in range(32):
        k[i + 4] = k[i] ^ t_transform2(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i])
        keys.append(k[i + 4])

    return keys


def get_chain_block(arr, baseIndex=0):
    return [
        arr[baseIndex + i * 4] << 24 | arr[baseIndex + 1 + i * 4] << 16 | arr[baseIndex + 2 + i * 4] << 8 | arr[
            baseIndex + 3 + i * 4]
        for i in range(4)
    ]


def do_block_crypt(block_data, round_keys):
    def t_transform1(z):
        b = tau_transform(z)
        c = b ^ rotate_left(b, 2) ^ rotate_left(b, 10) ^ rotate_left(b, 18) ^ rotate_left(b, 24)
        return c

    x_block = [0] * 36  # 创建一个长度为36的列表，初始化为0
    # 将blockData中的值复制到xBlock中
    for index, val in enumerate(block_data):
        x_block[index] = val

    # 进行32轮加密处理
    for i in range(32):
        x_block[i + 4] = (x_block[i] ^
                          t_transform1((x_block[i + 1] ^
                                        x_block[i + 2] ^
                                        x_block[i + 3] ^
                                        round_keys[i])))

    # 取最后一轮的输出作为结果
    y_block = [x_block[35], x_block[34], x_block[33], x_block[32]]
    return y_block


def check(name, s):
    if not s or len(s) != 16:
        print(f"{name} should be a 16 bytes string.")
        return False
    return True


#
# def encrypt_cbc(plaintext, key, iv, mode='base64'):
#     if not check("iv", iv) or not check("key", key):
#         return None
#
#     encryptd_round_keys = encrypt_round_keys(string_to_array(key))
#     plain_byte_array = string_to_array(plaintext)
#     print(plain_byte_array)
#     padded = NoPadding(plain_byte_array)
#     block_times = len(padded) // UINT8_BLOCK
#     out_array = bytearray()
#
#     # 初始化链式结构使用 iv (转换为 uint32 块)
#     chain_block = get_chain_block(string_to_array(iv))
#     for i in range(block_times):
#         # 提取当前轮要加密的 16 字节数据块
#         round_index = i * UINT8_BLOCK
#         block = get_chain_block(padded, round_index)
#         # 异或链式块
#         for j in range(4):
#             chain_block[j] ^= block[j]
#         # 使用链式块进行加密
#         cipher_block = do_block_crypt(chain_block, encryptd_round_keys)
#         # 使密文块成为下一个链式块的一部分
#         chain_block = cipher_block
#         # 将加密块转换为字节并添加到输出数组
#         for l in range(UINT8_BLOCK):
#             out_array.append((cipher_block[l // 4] >> ((3 - l) % 4 * 8)) & 0xff)
#
#     # 密文数组转换为字符串
#     if mode == 'base64':
#         return base64.b64encode(out_array)
#     else:
#         # 文本模式
#         return bytes(out_array).decode('utf-8', errors='ignore')


from ._constant import *
from ..models._sm4_options import SM4Options
from ..pad import pad
from ..mode import mode
import base64


class SM4:
    @staticmethod
    def encrypt(data: str, key: str, options: SM4Options | dict | str, padding: str = 'Pkcs7',
                iv: str | None = None,
                decode_mode='base64'):
        if isinstance(options, dict):
            options = SM4Options(**options)
        if isinstance(options, str):
            options = SM4Options(mode=eval(f'mode.{options}'), padding=eval(f'pad.{padding}'), iv=iv)
        padding = options.padding
        iv = options.iv
        match options.mode:
            case [mode.ECB, 'ECB']:
                # 检查 iv 和 key 是否合法
                if len(key) != UINT8_BLOCK:
                    raise ValueError("Key must be 16 bytes long")
                encryptd_round_keys = encrypt_round_keys(string_to_array(key))
                plain_byte_array = string_to_array(data)
                padded = padding(plain_byte_array)
                out_array = bytearray()

                for i in range(len(padded) // UINT8_BLOCK):
                    round_index = i * UINT8_BLOCK
                    block = get_chain_block(padded, round_index)
                    # 直接加密块，没有链式结构
                    cipher_block = do_block_crypt(block, encryptd_round_keys)
                    # 将加密块转换为字节并添加到输出数组
                    for l in range(UINT8_BLOCK):
                        out_array.append((cipher_block[l // 4] >> ((3 - l) % 4 * 8)) & 0xff)

                    # 密文数组转换为字符串
                if decode_mode == 'base64':
                    return base64.b64encode(out_array)
                else:
                    # 文本模式
                    return bytes(out_array)

            case mode.CBC:
                # 检查 iv 和 key 是否合法
                if not check("iv", iv) or not check("key", key):
                    return None
                encryptd_round_keys = encrypt_round_keys(string_to_array(key))
                plain_byte_array = string_to_array(data)
                padded = padding(plain_byte_array)
                block_times = len(padded) // UINT8_BLOCK
                out_array = bytearray()

                # 初始化链式结构使用 iv (转换为 uint32 块)
                chain_block = get_chain_block(string_to_array(iv))
                for i in range(block_times):
                    # 提取当前轮要加密的 16 字节数据块
                    round_index = i * UINT8_BLOCK
                    block = get_chain_block(padded, round_index)
                    # 异或链式块
                    for j in range(4):
                        chain_block[j] ^= block[j]
                    # 使用链式块进行加密
                    cipher_block = do_block_crypt(chain_block, encryptd_round_keys)
                    # 使密文块成为下一个链式块的一部分
                    chain_block = cipher_block
                    # 将加密块转换为字节并添加到输出数组
                    for l in range(UINT8_BLOCK):
                        out_array.append((cipher_block[l // 4] >> ((3 - l) % 4 * 8)) & 0xff)

                # 密文数组转换为字符串
                if decode_mode == 'base64':
                    return base64.b64encode(out_array)
                else:
                    # 文本模式
                    return bytes(out_array)
        pass

    @staticmethod
    def decrypt(_data, key, options):
        pass
