#!/usr/bin/python
# -*- coding: utf-8 -*-

from Crypto.Util.number import *
import gmpy
import sys, os, signal, string
from hashlib import *
import random
import inspect
from flag import flag

def genrandstr(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(N))

def isprintable(mystr):
    return all(c in string.printable for c in mystr)

def PoW():
    r = random.randint(0, 5)
    HASH = [md5, sha1, sha224, sha256, sha384, sha512]
    X = genrandstr(10)
    pr("Submit a printable string X, such that", HASH[r].__name__.split('_')[1] + "(X)[-6:] =", HASH[r](X).hexdigest()[-6:])
    Y = sc()
    return isprintable(Y) and HASH[r](Y).hexdigest()[-6:] == HASH[r](X).hexdigest()[-6:]

def vuln_to_dlp(nbit):
    p = getPrime(nbit)
    q = 2
    while True:
        q *= getPrime(random.randint(5, 16))
        if q > 2**(nbit - 1):
            if gmpy.is_prime(q+1) > 0:
                phi = (p-1) * q
                n = p*(q+1)
                while True:
                    e = random.randint(1, q)
                    d = gmpy.invert(e, phi)
                    if e * d % phi == 1:
                        return p, q+1, n, e, phi, d
            else:
                q = 2

def main():
    if not PoW():
        pr("+"*77)
        pr("| hi! Weird techniques combinations which sound gross but taste amazing!!!! |")
        pr("| we are preparing the unique challenge for you, please be patient with us! |")
        pr("+"*77)
        nbit = 512
        p, q, n, e, phi, d = vuln_to_dlp(nbit)
        while True:
            pr("| Options: \n|\t[E]ncryption oracle! \n|\t[F]lag oracle! \n|\t[P]hirypt oracle! \n|\t[Q]uit oracle!")
            ans = sc().lower()
            if ans == 'e':
                pr("| please send an integer, m, to encrypt: ")
                m = sc().lower()
                if m.isdigit():
                    pr("| pow(%s, e, n) = %s" % (int(m), pow(int(m), e, n)))
                else:
                    pr("| this oracle just encrypts integers!!")
            elif ans == 'f':
                pr("| pow(e * bytes_to_long(flag), e, n) = %s" % pow(e * bytes_to_long(flag), e, n))
            elif ans == 'p':
                pr('please send an integer, a, to phirypt: ')
                a = sc().lower()
                if a.isdigit():
                    pr("| %s %s φ (n) = %s" % (int(a), '%', int(a) % phi))
                else:
                    pr("| non integer detect3d!!")
            elif ans == 'q':
                die("Quiting ...")
            else:
                die("Bye ...")
    else:
        die('You must pass this PoW challenge :P')

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

if __name__ == '__main__':
    main()