import numpy as np
from math import sqrt, gcd
from Crypto.Util.number import inverse, long_to_bytes
from sage.all import *

def lagrange(b1,b2):
    mu = 1
    while mu != 0:
        mu = round((b1*b2) / (b1*b1))
        b2 -= mu*b1
        if b1*b1 > b2*b2:
            b1, b2 = b2, b1
    return b1, b2

def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m

public_key = (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
encrypted_flag = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523

q,h = public_key

alpha = 1
u = vector((1, h))
v = vector((0, q))

shortest, _ = lagrange(u, v)

f = shortest[0]
g = shortest[1]

print("f:", f)
print("g:", g)

flag = decrypt(q, h, f, g, encrypted_flag)
print(long_to_bytes(flag))

