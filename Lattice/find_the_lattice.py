import numpy as np
from math import sqrt, gcd
from Crypto.Util.number import inverse, long_to_bytes

def gauss_basis_reduction(u,v):
    if  sqrt(np.dot(u,u)) < sqrt(np.dot(v,v)):
        u,v = v, u
    while True:
        m = int(np.dot(u,v) / np.dot(u,u))
        if m == 0:
            return u, v
        v -= m * u

public_key = (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
encrypted_Flag = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523

private_key = gauss_basis_reduction(np.array(public_key), np.array([encrypted_Flag, 0]))[0]
print("Private key:", private_key)
def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m

print(private_key)
print(gcd(public_key[0], public_key[1]))
FLAG = decrypt(public_key[0], public_key[1], private_key[0], private_key[1], encrypted_Flag)
print(FLAG)