from sage.all import *
from Crypto.Util.number import *

def makexp(p, q):
    n = p * q
    R = IntegerModRing(n**2)
    L = p**3*(p-1)**2*q**3*(q-1)**2
    while True:
        d = getRandomRange(1, int(sqrt(sqrt(n))))
        if gcd(d, L) == 1:
            break
    e = inverse(d, L)
    return e, d

def genkey(nbit):
    p = getPrime(nbit)
    q = getPrime(nbit)
    n = p * q
    ##
    e, _ = makexp(p, q) # secret function that generate public exponent from prime factors!!!
    ##
    return (e, n)

# encryption

def encrypt_param(m, pubkey, a, b, c, d):
    m = bytes_to_long(m)
    e, n = pubkey
    R = IntegerModRing(n**2)
    M = Matrix(R, [[a, m], [b*n, c*n + d]])
    C = M ** e
    C = Matrix(R, [[C[0][0] % n, C[0][1] % n], [C[1][0], C[1][1]]])
    return C

def encrypt(m, pubkey):
    m = bytes_to_long(m)
    e, n = pubkey
    while True:
        a, b, c, d = [getRandomRange(1, n) for _ in range(4)]
        if gcd(a, n) * gcd(d, n) == 1:
            break
    R = IntegerModRing(n**2)
    M = Matrix(R, [[a, m], [b*n, c*n + d]])
    C = M ** e
    C = Matrix(R, [[C[0][0] % n, C[0][1] % n], [C[1][0], C[1][1]]])
    return C
