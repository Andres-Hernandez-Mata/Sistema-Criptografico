import json
import binascii
import base64
from nacl.signing import SigningKey
from nacl.hash import blake2b

# Sistema
def genKeyPair():
    kp = SigningKey.generate()
    pubKey = binascii.hexlify(kp.to_curve25519_private_key().public_key.__bytes__()).decode("utf-8")
    secKey = binascii.hexlify(kp.__bytes__())[0:64].decode("utf-8")
    return { "publicKey": pubKey, "secretKey": secKey}

def sign(msg, keyPair):
    if not 'publicKey' in keyPair or not 'secretKey' in keyPair:
        raise Exception("Invalid KeyPair: expected to find keys of name " +
                        "'secretKey' and 'publicKey': " +
                        json.dumps(keyPair))
    hshBin = hashBin(msg)
    hsh = base64UrlEncode(hshBin)
    signin_key = SigningKey(toTweetNaclSecretKey(keyPair))
    sigBin = signin_key.sign(hshBin).signature
    return {'hash': hsh, 'sig': binToHex(sigBin), 'pubKey': keyPair['publicKey']}

def toTweetNaclSecretKey(keyPair):
    if not 'publicKey' in keyPair or not 'secretKey' in keyPair:
        raise Exception("Invalid KeyPair: expected to find keys of name" +
                        " 'secretKey' and 'publicKey': " +
                        json.dumps(keyPair))
    return hexToBin(keyPair["secretKey"] + keyPair["publicKey"])

def binToHex(s: bytes):
    return binascii.hexlify(s).decode('UTF-8')

def hashBin(s):
    s = bytes(s, "utf-8")
    return binascii.unhexlify(blake2b(data=s, digest_size=32))

def base64UrlEncode(s: bytes):
    base = base64.urlsafe_b64encode(s)
    return base.decode("utf-8")

def hexToBin(h: str):
    return binascii.unhexlify(h)

def main():
    data: str = input("Insert message to sign: ")
    keys: dict = genKeyPair()
    signed: str = sign(data, keys)
    print(keys)
    print(signed)
    return 0

if __name__ == "__main__":
    main()


