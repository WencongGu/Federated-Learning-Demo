import rsa


# rsa加密，只能使用字符串
def rsaEncrypt(str):
    # 生成公钥、私钥
    (pubkey, privkey) = rsa.newkeys(512)
    print("pub: ", pubkey)
    print("priv: ", privkey)
    # 明文编码格式
    content = str.encode('utf-8')
    # 公钥加密
    crypto = rsa.encrypt(content, pubkey)
    return (crypto, privkey)


# rsa解密
def rsaDecrypt(str, pk):
    # 私钥解密
    content = rsa.decrypt(str, pk)
    con = content.decode('utf-8')
    return con


(a, b) = rsaEncrypt("hello")
print('加密后密文：')
print(a)
content = rsaDecrypt(a, b)
print('解密后明文：')

print(content)  