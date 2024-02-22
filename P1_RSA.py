# Algorithms Project 1 - RSA
# Objective: implement RSA Encryption and apply it to digital signature
import pandas as pd
import numpy as np
import sys
import hashlib


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
def getRandOddInt(numDigits):
    pArray = np.random.randint(10, size = numDigits)

    if(pArray[0] == 0 or (pArray[pArray.size - 1] % 2) == 0):
        return getRandOddInt(numDigits)

    counter = 1
    bigIntP = int(0)
    for i in pArray:
        bigIntP += int(int(i) * int(10 ** (numDigits - counter)))
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
    if int(b) == 0:
        return int(a), 1, 0

    passB = int(a % b)
    a = b

    u, v, w = extendedEuclid(a, passB)
    aDivb = int(int(a) // int(b))
    g, s, t = int(u), int(w), int((int(v) - int(aDivb) * int(w)))

    return int(g), int(s), int(t)

def secondExtendedEuclid(a, b):
    if a == 0:
        return b, 0, 1
    gcd, s, d = secondExtendedEuclid(b % a, a)
    #print("gcd, s, d =", gcd, s, d)
    return gcd, d - (b // a) * s, s

def modInverse(b, a):
    gcd, s, d = secondExtendedEuclid(a, b)
    #print("inverse s:", s)
    #print("inverse d:", d)
    return (d % a)

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
    print("n =", n)
    phiN = int(int(p - 1) * int(q - 1))
    print("phiN =", phiN)
    e = int(getE(phiN, numDigits))
    print("e:", e)
    #gcd, s, d = extendedEuclid(e, phiN)
    #print("g:", gcd)
    #print("s:", s)
    #print("t(d):", d)

    #de = int(d * e)
    #se = int(s * e)
    #deModPhiN = int(de) % int(phiN)
    #print("d * e =", de)
    #print("de mod phiN =", deModPhiN)

    inverse = modInverse(e , phiN)
    #print("Inverse of ", e, " is ", inverse)
    de = int(inverse * e)
    #se = int(s * e)
    deModPhiN = int(de) % phiN
    print("d * e =", de)
    print("de mod phiN =", deModPhiN)

    '''
    counter = 0
    while deModPhiN != 1 and counter < 100:

        # compute n from the 2 primes, phi of n, e, and d
        e = int(getE(phiN, numDigits))
        print("e:", e)
        gcd, s, d = extendedEuclid(phiN, e)
        print("g:", gcd)
        print("s:", s)
        print("t(d):", d)

        de = int(d * e)
        se = int(s * e)
        deModPhiN = int(de) % int(phiN)
        print("d * e =", de)
        print("de mod phiN =", deModPhiN)
        counter += 1
    print("counter =", counter)
    #print("s * e =", se)
    #print("se mod phiN =", int(se) % int(phiN))
    '''
    pq = pd.Series([p,q])
    en = pd.Series([e,n])
    dn = pd.Series([d,n])
    pq.to_csv("p_q.csv")
    en.to_csv("e_n.csv")
    dn.to_csv("d_n.csv")
    print("done with key generation!")

# given a file with a message and a RSA private key
# produces a signed file using a SHA256 hash
def Signing(doc, key):
    #match = False
    rawMsg = open(doc, 'r').read()

    # create the hash as a decimal to use in pow function
    h = int('0x' + hashlib.sha256(rawMsg.encode('utf-8')).hexdigest(), 0)

    # get the components of the key from the csv
    d = int(key.at[0, '0'])
    n = int(key.at[1, '0'])

    signed = pow(h, d, n)

    # write the original message to a file, then append the signaute on the last line
    signedDoc = open(doc + ".signed", 'w')
    signedDoc.write(rawMsg + '\n' + str(signed))
    signedName = signedDoc.name
    signedDoc.close()
    signedDoc = open(signedName, 'r')

    print("\nSigned\n", signedDoc.read())
    signedDoc.close()

def verification(doc, key):
    match = False
    message, signature = getMessageAndSignature(doc)

    # get the components of the key from the csv
    e = int(key.at[0, '0'])
    n = int(key.at[1, '0'])
    #print("The signature is: \n", int(signature))
    decodedSignature = pow(int(signature), int(e), int(n))
    messageHash = int('0x' + hashlib.sha256(message.encode('utf-8')).hexdigest(), 0)
    print("Decoded signature is: \n", decodedSignature)
    print("Message hash: \n", messageHash)
    print("The two match: ", decodedSignature == messageHash)

    #k = int(e * d)

    #print("e is:", e)
    #e = getE(phiN, int(2))


    p = int(8740585859854599967603419425149349020006339268012462485259213327299822497913990045529145254447284793948432056732938816865979613734125034173452915340311883)
    q = int(1008662020699151390175514732832665985272962248350721925088724316356384168965441891818706610549327279724266755786480887531405872862766004648293799023889587)
    n = int(p * q)
    phiN = int((p - 1) * (q - 1))
    gcd, s, d = extendedEuclid(phiN, e)
    dTimesE = int(d * e)


    dKey = pd.read_csv("d_n.csv")
    dRead = int(dKey.at[0, '0'])



    print("getE(phiN, numDigits) == e", e == getE(phiN, 154))
    #print("g is:", gcd)
    #print("s is:", s)
    #print("t is:", d)
    print("d == dRead", d == dRead )
    #print("p is:\n", p)
    #print("q is:\n", q)
    #print("phiN is:\n", phiN)
    #print("e is:\n", e)
    #print("gcd phiN and e:\n", gcd)
    #print("d is:\n", d)
    #print("n is:\n", n)
    #print("gcd phiN and e: ", getGCD(phiN, e))

    #print("dTimesE =\n", dTimesE)
    #print("phi of n:\n", phiN)
    #print("(d * e) % phiN =", int(dTimesE % phiN))
    #print("k is:\n", k)

    #print("is phiN greater than d * e", phiN > dTimesE)


    if match:
        print("\nAuthentic!")
    else:
        print("\nModified!")

# given a file name of a signed document
# returns the original message and signature within the file
def getMessageAndSignature(doc):
    signedMsg = open(doc, 'r').readlines()
    linesInFile = len(signedMsg)

    signature = signedMsg[linesInFile - 1]

    # first line of message
    message = trimNewline(signedMsg[0])

    # if message is more than 1 line
    # append each line to the message
    currentLine = 1
    while currentLine < linesInFile - 1:
        message += '\n' + trimNewline(signedMsg[currentLine])
        currentLine += 1

    return message, signature

# given a string removes the last character if it is a new line
def trimNewline(msg):
    msgLen = len(msg)
    if (msg[msgLen - 1]) == '\n':
        #print("found newline")
        return msg[:msgLen - 1]
    return msg

# No need to change the main function.
def main():
    # part I, command-line arguments will be: python yourProgram.py 1
    if int(sys.argv[1]) == 1:
        RSA_key_generation()
    # part II, command-line will be for example: python yourProgram.py 2 s file.txt
    #                                       or   python yourProgram.py 2 v file.txt.signed
    else:
        (task, fileName) = sys.argv[2:]
        if "s" in task:
            doc = fileName
            key = pd.read_csv("d_n.csv")

            Signing(doc, key)

        else:
            # do verification
            doc = fileName
            key = pd.read_csv("e_n.csv")
            verification(doc, key)

    print("done!")


if __name__ == '__main__':
    main()
