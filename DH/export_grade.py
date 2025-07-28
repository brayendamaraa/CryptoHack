from pwn import *
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from sage.all import *

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
    
# Intercept from Alice
conn = remote('socket.cryptohack.org', 13379)
data = conn.recvline()
idx = data.index(b'{')
data = json.loads(data[idx:])
print(type(data))
data = {'supported': ['DH64']}

# from Alice to Bob
conn.send(json.dumps(data))

# Intercept from Bob
data = conn.recvline()
idx = data.index(b'{')
data = json.loads(data[idx:])

conn.send(json.dumps(data))

# Intercept from Alice
alice_public = conn.recvline()
idx = alice_public.index(b'{')
alice_public = json.loads(alice_public[idx:])
print(alice_public)

# Intercept from Bob
bob_public = conn.recvline()
idx = bob_public.index(b'{')
bob_public = json.loads(bob_public[idx:])
print(bob_public)

# Ciphertext from Alice
ciphertext = conn.recvline()
idx = ciphertext.index(b'{')
ciphertext = json.loads(ciphertext[idx:])
print(ciphertext)

p = Integer(alice_public['p'])
g = Integer(alice_public['g'])
A = Integer(alice_public['A'])
B = Integer(bob_public['B'])

F = GF(p)
g = F(g)
A = F(A)
B = F(B)

alice_secret = discrete_log(A, g)
shared_secret = pow(B, alice_secret, p)
print(shared_secret)


iv = ciphertext['iv']
ciphertext = ciphertext['encrypted_flag']
flag = decrypt_flag(shared_secret, iv, ciphertext)
print(flag)
conn.close()