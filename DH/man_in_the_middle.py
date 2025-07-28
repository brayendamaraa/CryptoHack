from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from pwn import *
import json

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

conn = remote('socket.cryptohack.org', 13371)

data = conn.recvline()
idx = data.index(b'{')
data = json.loads(data[idx:])
print(data)

data['p'] = hex(1)
conn.send(json.dumps(data))

data = conn.recvline()
idx = data.index(b'{')
data = json.loads(data[idx:])
print(data)

conn.send(json.dumps(data))

ciphertext = conn.recvline()
idx = ciphertext.index(b'{')
ciphertext = json.loads(ciphertext[idx:])
print(ciphertext)

shared_secret = 0x0
iv = ciphertext['iv']
ciphertext = ciphertext['encrypted_flag']
flag = decrypt_flag(shared_secret, iv, ciphertext)
print(flag)
conn.close()