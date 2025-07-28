from sage.all import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def decrypt_flag(data: dict, shared_secret: int):

    ciphertext = bytes.fromhex(data['encrypted_flag'])
    iv = bytes.fromhex(data['iv'])

    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]

    # Decrypt flag
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), 16)
    return decrypted

# Define Curve params
p = 1331169830894825846283645180581
E = EllipticCurve(GF(p), [-35,98])
G = E.gens()[0]
A = E(1110072782478160369250829345256, 800079550745409318906383650948)
B = E(1290982289093010194550717223760, 762857612860564354370535420319)

data = {'iv': 'eac58c26203c04f68d63dc2c58d79aca', 'encrypted_flag': 'bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'}

# Step 2: Compute order of G
r = G.order()
print(f"Order of G = {r}")

# Step 3: Find embedding degree k such that r divides p^k - 1
embedding_k = None
for k in range(1, 1000):
    if (p**k - 1) % r == 0:
        embedding_k = k
        print(f"Found embedding degree: k = {k}")
        break

if embedding_k is None:
    print("No suitable embedding degree found — MOV attack not possible.")
    raise SystemExit()

# Step 4: Define field extension and curve over that field
Fpk = GF(p**embedding_k, 'z')
E_ext = EllipticCurve(Fpk, [-35, 98])
G_ext = E_ext(G.xy())
A_ext = E_ext(A.xy())
R_ext = E_ext.random_point()

m = R_ext.order()
d = gcd(m, r)
T_ext = (m // d) * R_ext

g = G_ext.weil_pairing(T_ext, r)
a = A_ext.weil_pairing(T_ext, r)

# Step 6: Solve discrete log in Fpk*
print("Solving DLP...")
a_secret = a.log(g)
print(f"Recovered private key a = {a}")

shared_point = a_secret * B
shared_secret = shared_point.x()

FLAG = decrypt_flag(data, shared_secret)
print(FLAG)