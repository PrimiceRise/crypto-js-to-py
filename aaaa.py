import base64
from crypto_py import CryptoPY
Pkcs7 = CryptoPY.pad.Pkcs7
NoPadding = CryptoPY.pad.NoPadding
UINT8_BLOCK = 16

Sbox = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]
FK = [
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
]


# 以下是部分函数的转换示例

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


# 其他函数的转换也需要按照JavaScript的逻辑来实现


def encrypt_round_keys(key):
    def t_transform2(z):
        b = tau_transform(z)
        c = b ^ rotate_left(b, 13) ^ rotate_left(b, 23)
        return c

    keys = []
    mk = [
        key[0 + i*4] << 24 | key[1 + i*4] << 16 | key[2 + i*4] << 8 | key[3 + i*4]
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
        arr[baseIndex + i*4] << 24 | arr[baseIndex + 1 + i*4] <<16 | arr[baseIndex + 2 + i*4] << 8 | arr[baseIndex + 3 + i*4]
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

def de_padding(padded_buffer):
    if padded_buffer is None:
        return None
    original_buffer = padded_buffer[:-padded_buffer[-1]]  # 切片操作去除填充
    return original_buffer


def check(name, s):
    if not s or len(s) != 16:
        print(f"{name} should be a 16 bytes string.")
        return False
    return True


def encrypt_cbc(plaintext, key, iv, mode='base64'):
    if not check("iv", iv) or not check("key", key):
        return None

    encryptd_round_keys = encrypt_round_keys(string_to_array(key))
    plain_byte_array = string_to_array(plaintext)
    padded = Pkcs7(plain_byte_array)
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
    if mode == 'base64':
        return base64.b64encode(out_array)
    else:
        # 文本模式
        return bytes(out_array).decode('utf-8', errors='ignore')


def test_encrypt_cbc():
    return encrypt_cbc('123123', 'Wwcd@2016@0309#!', 'Wwcd@2016@03VI#!')

def encrypt_ecb(plaintext, key, mode='base64'):
    # 检查密钥长度是否为16字节
    if len(key) != UINT8_BLOCK:
        raise ValueError("Key must be 16 bytes long")

    # 生成加密轮密钥
    encryptd_round_keys = encrypt_round_keys(string_to_array(key))

    # 将明文转换为字节数组，并进行填充
    plain_byte_array = string_to_array(plaintext)
    padded = Pkcs7(plain_byte_array)  # 使用PKCS7填充方法

    # 初始化输出数组
    out_array = bytearray()

    # 对每个块进行加密
    block_times = len(padded) // UINT8_BLOCK
    print(block_times)
    for i in range(block_times):
        round_index = i * UINT8_BLOCK
        block = get_chain_block(padded, round_index)
        # 直接加密块，没有链式结构
        cipher_block = do_block_crypt(block, encryptd_round_keys)
        # 将加密块转换为字节并添加到输出数组
        for l in range(UINT8_BLOCK):
            out_array.append((cipher_block[l // 4] >> ((3 - l) % 4 * 8)) & 0xff)

    # 密文数组转换为字符串
    if mode == 'base64':
        return base64.b64encode(out_array)
    else:
        # 文本模式
        return bytes(out_array).decode('utf-8', errors='ignore')

def test_encrypt_ecb():
    return encrypt_ecb('123123', 'Wwcd@2016@0309#!')

print(test_encrypt_cbc().decode())
print(test_encrypt_cbc().decode() == "PMSPJ1+Xzj5bMOnco983cw==")
print(test_encrypt_ecb().decode())
print(test_encrypt_ecb().decode() == "sBp0G8n72eOVDqmVVNbdpw==")
