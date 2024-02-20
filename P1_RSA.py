# Algorithms Project 1 - RSA
# Objective: implement RSA Encryption and apply it to digital signature
import pandas as pd
import numpy as np
import sys


# check if p is prime (most likely a prime)
def FermatPrimalityTest(p):
    print(p)
    a = False
    # to be completed
    return a


def RSA_key_generation():
    p = 7
    q = 13
    n = p*q
    e = 3
    d = 5
    # to be completed
    pq = pd.Series([p,q])
    en = pd.Series([e,n])
    dn = pd.Series([d,n])
    pq.to_csv("p_q.csv")
    en.to_csv("e_n.csv")
    dn.to_csv("d_n.csv")
    print("done with key generation!")


def Signing(doc, key):
    match = False
    # to be completed
    print("\nSigned ...")


def verification(doc, key):

    match = False
    # to be completed
    if match:
        print("\nAuthentic!")
    else:
        print("\nModified!")


# No need to change the main function.
def main():
    # part I, command-line arguments will be: python yourProgram.py 1
    if int(sys.argv[1]) == 1:
        RSA_key_generation()
    # part II, command-line will be for example: python yourProgram.py 2 s file.txt
    #                                       or   python yourProgram.py 2 v file.txt.signed
    else:
        (task, fileName) = sys.argv[2:]
        if "s" in task:  # do signing
            doc = None  # you figure out
            key = None  # you figure out
            Signing(doc, key)
        else:
            # do verification
            doc = None   # you figure out
            key = None   # you figure out
            verification(doc, key)

    print("done!")


if __name__ == '__main__':
    main()
