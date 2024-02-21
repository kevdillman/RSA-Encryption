# Algorithms Project 1 - RSA
# Objective: implement RSA Encryption and apply it to digital signature
import pandas as pd
import numpy as np
import sys


# check if p is prime (most likely a prime)
def FermatPrimalityTest(p):
    fermatTest = True
    sizeOfA = 9

    a = getRandOddInt(sizeOfA)
    if pow(a, p - 1, p) != 1:
        fermatTest = False

    a = getRandOddInt(sizeOfA)
    if pow(a, p - 1, p) != 1:
        fermatTest = False

    return fermatTest

# gets a likely prime number with decimal digits equal to size
def getPrime(size):
    num = getRandOddInt(size)
    counter = 0

    while not FermatPrimalityTest(num):
        num = getRandOddInt(size)
        counter += 1

    print("Took", counter, "tries to find the prime number: \n", num)
    return num

# gets a random odd number of the given number of digits in integer and array forms
def getRandOddInt(size):
    pArray = np.random.randint(10, size = 154)

    if(pArray[0] == 0 or (pArray[pArray.size - 1] % 2) == 0):
        return getRandOddInt(size)

    counter = 0
    bigIntP = int(0)
    for i in pArray:
        bigIntP += int(int(i) * int(10 ** (153 - counter)))
        counter += 1

    return bigIntP

# uses Euclid's method to find greatest common divisor
def getGCD(x, y):
    if y == 0:
        return x
    return(getGCD(y, int(x % y)))

# given phi of n and a number of digits finds an e to use in rsa
def getE(phiN, size):
    e = getRandOddInt(size)

    while getGCD(phiN, e) > 1:
        e = getRandOddInt(size)

    return e

# returns the gcd, and multiplicative inverse of a and b
def extendedEuclid(a, b):
    if b == 0:
        return a, 1, 0

    u, v, w = extendedEuclid(b, a % b)
    g, s, t = u, w, (v - int(a / b) * w)

    return g, s, t

# generates an RSA public and private key
def RSA_key_generation():
    numDigits = 154
    p = 7
    q = 13
    n = p*q
    e = 3
    d = 5

    # find 2 prime numbers
    p = getPrime(numDigits)
    q = getPrime(numDigits)

    # ensures the same prime numbers have not been chosen
    while q == p:
        q = getPrime(numDigits)

    # compute n from the 2 primes, phi of n, e, and d
    n = int(p * q)
    phiN = int((p - 1) * (q - 1))
    e = getE(phiN, numDigits)
    gcd, _, d = extendedEuclid(phiN, e)

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
