from random import randint

P = 2
N = 50
E = 31337

FLAG = b'crypto{FLAG_PLACEHOLDER}'

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


mat = generate_mat()

def matrix_to_key(M):
    return tuple(tuple(row) for row in M.rows())

def dlp_bsgs_matrix(A, B, order_bound):
    from math import ceil, sqrt
    F = A.base_ring()
    n = A.nrows()
    m = ceil(sqrt(order_bound))

    # Precompute baby steps
    baby_steps = {}
    Aj = identity_matrix(F, n)
    for j in range(m):
        baby_steps[matrix_to_key(Aj)] = j
        Aj = Aj * A

    # Precompute A^{-m}
    Ainv = A.inverse()
    Ainv_m = Ainv^m

    # Giant steps
    gamma = B
    for i in range(m):
        key = matrix_to_key(gamma)
        if key in baby_steps:
            j = baby_steps[key]
            return i * m + j
        gamma = Ainv_m * gamma

    return None

dlp_bsgs_matrix(mat, mat^E, mat.multiplicative_order())