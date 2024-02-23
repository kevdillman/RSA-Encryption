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

    # converts the array of individual integers into a single integer
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

# implements the extended euclidian algorithm
def extendedEuclid(a, b):
    if a == 0:
        return b, 0, 1

    gcd, s, d = extendedEuclid(b % a, a)

    return gcd, int(d - (b // a) * s), int(s)

# gets the modular inverse from the extended euclidian algorithm
def modInverse(b, a):
    gcd, s, d = extendedEuclid(a, b)
    return (int(d) % int(a))

# generates an RSA public and private key
def RSA_key_generation():
    numDigits = 165
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
    phiN = int(int(p - 1) * int(q - 1))
    e = int(getE(phiN, numDigits // 2))
    d = int(modInverse(e , phiN))

    pq = pd.Series([p,q])
    dn = pd.Series([d,n], dtype = str)
    en = pd.Series([e,n], dtype = str)

    pq.to_csv("p_q.csv")
    en.to_csv("e_n.csv")
    dn.to_csv("d_n.csv")
    print("done with key generation!")

# given a file with a message and a RSA private key
# produces a signed file using a SHA256 hash
def Signing(doc, key):

    rawMsg = open(doc, 'r').read()

    # create the hash as a decimal to use in pow function
    h = int('0x' + hashlib.sha256(rawMsg.encode('utf-8')).hexdigest(), 0)

    # get the components of the key from the csv
    d = int(key.at[0, '0'])
    n = int(key.at[1, '0'])

    # encrypt the hash with the private key
    signed = pow(h, d, n)

    # write the original message to a file, then append the signature on the last line
    signedDoc = open(doc + ".signed", 'w')
    signedDoc.write(rawMsg + '\n' + str(signed))
    signedName = signedDoc.name
    signedDoc.close()

    signedDoc = open(signedName, 'r')
    print(signedDoc.read(), "\nSigned\n", )
    signedDoc.close()

def verification(doc, key):
    match = False

    # get the components of the key from the csv
    e = int(key.at[0, '0'])
    n = int(key.at[1, '0'])

    # parse the message and signature out from the signed file
    message, signature = getMessageAndSignature(doc)

    # decode the signature and calculate the message hash
    decodedSignature = pow(int(signature), int(e), int(n))
    messageHash = int('0x' + hashlib.sha256(message.encode('utf-8')).hexdigest(), 0)

    # verify the decoded signature matches the message's hash
    match = decodedSignature == messageHash

    if match:
        print("\nAuthentic!")
    else:
        print("\nModified!")

# given a file name of a signed document
# returns the original message and signature within the file
def getMessageAndSignature(doc):
    signedMsg = open(doc, 'r').readlines()
    linesInFile = len(signedMsg)

    # reads the signature off the last line of the file
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
            doc = fileName
            key = pd.read_csv("e_n.csv")

            verification(doc, key)

    print("done!")


if __name__ == '__main__':
    main()
