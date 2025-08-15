from random import random, randint

P = 2
N = 50
E = 31337

def bytes_to_binary(s):
    bin_str = ''.join(format(b, '08b') for b in s)
    bits = [int(c) for c in bin_str]
    return bits

def generate_mat():
    while True:
        msg = bytes_to_binary(FLAG)
        msg += [randint(0, 1) for _ in range(N*N - len(msg))]

        rows = [msg[i::N] for i in range(N)]
        mat = Matrix(GF(2), rows)

        if mat.determinant() != 0 and mat.multiplicative_order() > 10^12:
            return mat

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

def save_matrix(M, fname):
    open(fname, 'w').write('\n'.join(''.join(str(x) for x in row) for row in M))

def flatten_matrix(M):
    """
    Flatten a Sage matrix into a flat tuple (row-major order).
    """
    return tuple(M.list()) 

def bitstring_to_bytes(bitstring):
    """
    Converts a binary string like '110101' into a bytes object.
    Pads the string on the left with zeros to make a multiple of 8.
    """
    bitstring = bitstring.zfill((len(bitstring) + 7) // 8 * 8)  # pad to multiple of 8 bits
    return int(bitstring, 2).to_bytes(len(bitstring) // 8, byteorder='big')

mat = load_matrix('flag.enc')

m_ord = mat.multiplicative_order()

for i in range(1,10^6):
    n = i * m_ord
    if gcd(n, E) != 1:
        continue
    D = pow(int(E), int(-1), int(n))
    M = mat^D
    msg = flatten_matrix(M)
    FLAG = bitstring_to_bytes(''.join(map(str, msg)))
    if FLAG.startswith(b'crypto{'):
        print(FLAG)
        break

# D = pow(E, -1, mat.multiplicative_order())

# M = mat^D
# msg = flatten_matrix(M)
# FLAG = bitstring_to_bytes(''.join(map(str, msg)))
# print(FLAG)