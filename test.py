from crypto_py import SMPY, CryptoPY

""" 
AES 示例
"""

data = "如意如意，按我心意，快快显灵"

AESkey = "This_is_a_key!!!"
AESiv = "This_is_a_iv_!!!"

print(f"{data = }")
print(f"{AESkey = }")
print(f"{AESiv = }")
print()

# AES ECB MODE
def aes_ecb():
    key = CryptoPY.enc.Utf8.parse(AESkey)

    options = CryptoPY.Options(
        mode=CryptoPY.mode.ECB,
        padding=CryptoPY.pad.Pkcs7
    )
    encrypted = CryptoPY.AES.encrypt(data, key, options)
    cipher = encrypted.ciphertext
    print("AES-ECB 加密:",encrypted.decode())
    print("AES-ECB 加密ciphertext:",cipher.decode())

    decrypt = CryptoPY.AES.decrypt(encrypted.decode(), key, {
        "mode": CryptoPY.mode.ECB,
        "padding": CryptoPY.pad.Pkcs7
    })
    cipher_decrypt = CryptoPY.AES.decrypt(cipher.decode(), key, "ECB", "Pkcs7").ciphertext
    print("AES-ECB 解密:",decrypt.decode())
    print("AES-ECB 解密ciphertext:",cipher_decrypt.decode())


# AES CBC MODE
def aes_cbc():
    key = CryptoPY.enc.Utf8.parse(AESkey)
    iv = CryptoPY.enc.Utf8.parse(AESiv)

    options = CryptoPY.Options(
        iv=iv,
        mode=CryptoPY.mode.CBC,
        padding=CryptoPY.pad.Pkcs7
    )
    encrypted = CryptoPY.AES.encrypt(data, key, options)
    cipher = encrypted.ciphertext
    print("AES-CBC 加密:",encrypted.decode())
    print("AES-CBC 加密ciphertext:",cipher.decode())

    decrypt = CryptoPY.AES.decrypt(encrypted.decode(), key, {
        "iv": iv,
        "mode": CryptoPY.mode.CBC,
        "padding": CryptoPY.pad.Pkcs7
    })
    cipher_decrypt = CryptoPY.AES.decrypt(cipher.decode(), key, "CBC", "Pkcs7", iv).ciphertext
    print("AES-CBC 解密",decrypt.decode())
    print("AES-CBC 解密ciphertext",cipher_decrypt.decode())


# SM4
def sm4_test():

    options = CryptoPY.Options(
        iv=AESiv,
        mode=CryptoPY.mode.CBC,
        padding=CryptoPY.pad.Pkcs7
    )
    encrypted = SMPY.SM4.encrypt(data, AESkey, options)
    print("SM4-CBC 加密：",encrypted.decode())


    decrypt = SMPY.SM4.decrypt(encrypted.decode(), AESkey, "CBC", "Pkcs7", AESiv)
    print("SM4-CBC 解密：",decrypt.decode())

    encrypted = SMPY.SM4.encrypt(data, AESkey, {
        "mode": SMPY.mode.ECB,
        "padding": SMPY.pad.Pkcs7
    }).decode()
    print("SM4-ECB 加密：",encrypted)
    decrypted = SMPY.SM4.decrypt(encrypted,AESkey, {
        "mode": SMPY.mode.ECB,
        "padding": SMPY.pad.Pkcs7
    }).decode()
    print("SM4-ECB 解密：",decrypted)

aes_ecb()
print()
aes_cbc()
print()
sm4_test()