from pwn import *
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from sage.all import *

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, encrypted_flag: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    encrypted_flag = bytes.fromhex(encrypted_flag)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted_flag)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')
    

conn = remote("socket.cryptohack.org", 13380)
conn.recvuntil("Intercepted from Alice: ")
a_data = conn.recvline()
a_data = json.loads(a_data)

conn.recvuntil("Intercepted from Bob: ")
b_data = conn.recvline()
b_data = json.loads(b_data)

conn.recvuntil("Intercepted from Alice: ")
ciphertext = conn.recvline()
ciphertext = json.loads(ciphertext)

p = int(a_data['p'],0)
g = int(a_data['g'],0)
A = int(a_data['A'],0)
B = int(b_data['B'],0)

a_secret = A*pow(g,-1,p)
shared_secret = (a_secret * B) % p

iv = ciphertext['iv']
encrypted_flag = ciphertext['encrypted']
FLAG = decrypt_flag(shared_secret, iv, encrypted_flag)
print(FLAG)