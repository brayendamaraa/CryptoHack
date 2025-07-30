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
    
conn = remote("socket.cryptohack.org", 13373)
conn.recvuntil(b'Intercepted from Alice: ')
a_secret = json.loads(conn.recvline())

p = a_secret['p']
g = a_secret['g']
A = a_secret['A']

a_secret['g'] = A
a_secret['A'] = "0x01"

print(a_secret)

conn.recvline()

conn.recvuntil(b'Intercepted from Alice: ')
data = json.loads(conn.recvline())
iv = data['iv']
ciphertext = data['encrypted']

conn.sendline(json.dumps(a_secret))

conn.recvuntil(b'Bob says to you: ')
shared_secret = int(json.loads(conn.recvline())['B'],16)

FLAG = decrypt_flag(shared_secret, iv, ciphertext)
print(FLAG)