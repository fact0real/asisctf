#!/usr/bin/env python
# -- encoding: UTF-8 --

from fractions import gcd
import sys, os, signal, string, inspect
from hashlib import sha224, sha256, sha384, sha512
from random import choice
from flag import flag
from Crypto.Util.number import *

def genrandstr(N):
    return ''.join(choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(N))

def isprintable(mystr):
    return all(c in string.printable for c in mystr)

def PoW():
    HASH = [sha224, sha256, sha384, sha512]
    r = getRandomRange(0, 3)
    X = genrandstr(10)
    bound = 6 # after runing the CTF, I will decrease to 6!
    pr("Submit a printable string X, such that", HASH[r].__name__ + "(X)[-" + str(bound) + ":] =", HASH[r](X).hexdigest()[-bound:]) 
    Y = sc()
    return isprintable(Y) and HASH[r](Y).hexdigest()[-bound:] == HASH[r](X).hexdigest()[-bound:]

def main():
    pr("-"*72)
    pr('''
     _     _   _ ____    _      ____                                _
    | |   | \ | / ___|  / \    | __ ) _   _ _ __ __ _  ___ _ __    | |
    | |   |  \| \___ \ / _ \   |  _ \| | | | '__/ _` |/ _ \ '__|   | |
    | |   | |\  |___) / ___ \  | |_) | |_| | | | (_| |  __/ |      | |
    | |   |_| \_|____/_/   \_\ |____/ \__,_|_|  \__, |\___|_|      | |
    |_|                                         |___/              |_|
    ''')
    pr("-"*72)
    if PoW():
        pr("| NSA is cooking a burger, be patinet!|")
        from heavy_part import genkey, makexp, encrypt, encrypt_param # just for better performance
        pubkey = genkey(512)
        e, n = pubkey
        pr("|  🍔  your burger is ready to flip!!!|")
        pr("|-------------------------------------|")
        pr("| Options: 	  	              |\n|\t[K]ey generation algorithm    |\n|\t[E]ncryption function         |\n|\t[P]ublic key                  |\n|\t[C]ipher Flag                 |\n|\t[H]elp!                       |\n|\t[Q]uit                        |")
        pr("|-------------------------------------|")
        while True:
            pr('| choose an option: ')
            ans = sc().lower()
            if ans == 'k':
                pr(inspect.getsource(genkey))
            elif ans == 'e':
                pr(inspect.getsource(encrypt))
                pr('| you can encrypt any message, send the plaintext and get encrypted message!!')
                msg = sc()
                enc = encrypt(msg, pubkey)
                pr('| the encrypted message is 2x2 matrix C =', enc)
            elif ans == 'p':
                #pr('| the public key (e, n) = (' + str(e) + (', ') + str(n) + ')')
                pr('| the public key is secret too! huh? why?!!!')
            elif ans == 'c':
                pr('| the cipher flag or encrypted flag is 2x2 matrix C =', encrypt(flag, pubkey))
            elif ans == 'h':
                pr('| for simplicity we have added an option that you can encrypt any message with desired random parameters by pulic key!!!')
                pr('| send us four random integer parameters seperated by comma: ')
                try:
                    parameters = sc().split(',')
                    a, b, c, d = [int(i) for i in parameters]
                    if gcd(a, n) == gcd(d, n) == 1:
                        pr('| send the message:')
                        m = sc()
                        C = encrypt_param(m, pubkey, a, b, c, d)
                        pr('| the encrypted message is 2x2 matrix C =', C)
                    else:
                        pr('| the parameters NOT satisfying the condition!')
                except:
                    pr('| please send 4 integer smaller than modulus n :|')
            elif ans == 'q':
                die("Quiting ...")
            else:
                die('You should have valid choise, Bye!')
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
