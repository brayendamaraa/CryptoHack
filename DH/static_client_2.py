from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import isPrime
import hashlib
from pwn import *
import json
from sympy.ntheory.residue_ntheory import discrete_log


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
    
def smooth_p(p):
    i = 1
    val = 1
    while True:
        val *= i
        if isPrime(val + 1) and (val + 1).bit_length() > p.bit_length():
            return val + 1
        i += 1

    
conn = remote("socket.cryptohack.org", 13378)
conn.recvuntil(b"Intercepted from Alice: ")
a_data = json.loads(conn.recvline())
p = int(a_data['p'], 16)

conn.recvline()

conn.recvuntil(b"Intercepted from Alice: ")
data = json.loads(conn.recvline())
iv = data['iv']
ciphertext = data['encrypted']

smooth_p = smooth_p(p)
print(isPrime(smooth_p))
print(smooth_p.bit_length())
print(p.bit_length())

resp = {"p": hex(smooth_p), "g": a_data['g'], "A": a_data['A']}
conn.sendline(json.dumps(resp))

conn.recvuntil(b"Bob says to you: ")
b_data = json.loads(conn.recvline())
B = int(b_data['B'], 16)

b_secret = discrete_log(smooth_p, B, 2)
shared_secret = pow(int(a_data['A'], 16), b_secret, p)
print(type(shared_secret))

FLAG = decrypt_flag(shared_secret, iv, ciphertext)
print(FLAG)