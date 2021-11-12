import json
import binascii
import base64
from os import write
from nacl.signing import SigningKey
from nacl.hash import blake2b


def genKeyPair():
    kp = SigningKey.generate()
    pubKey = binascii.hexlify(kp.to_curve25519_private_key().public_key.__bytes__()).decode("utf-8")
    secKey = binascii.hexlify(kp.__bytes__())[0:64].decode("utf-8")
    return { "publicKey": pubKey, "secretKey": secKey}

def sign(msg, keyPair):
    if not 'publicKey' in keyPair or not 'secretKey' in keyPair:
        raise Exception("Invalid KeyPair: expected to find keys of name 'secretKey' and 'publicKey': " + json.dumps(keyPair))
    hshBin = hashBin(msg)
    hsh = base64UrlEncode(hshBin)
    signin_key = SigningKey(toTweetNaclSecretKey(keyPair))
    sigBin = signin_key.sign(hshBin).signature
    return {'usuario': msg, 'hash': hsh, 'sig': binToHex(sigBin), 'pubKey': keyPair['publicKey']}

def toTweetNaclSecretKey(keyPair):
    if not 'publicKey' in keyPair or not 'secretKey' in keyPair:
        raise Exception("Invalid KeyPair: expected to find keys of name 'secretKey' and 'publicKey': " + json.dumps(keyPair))
    return hexToBin(keyPair["secretKey"] + keyPair["publicKey"])

def writeBinary(data: str, path: str):
    with open(path, 'w') as file:
        file.write(data)
    return 0

def bytesToIntArray(data: bytes):
    data_array: list = []
    for d in data:
        data_array.append(d)
    return data_array

def intBytesToCharBytes(data: list):
    fromArray: list = []
    for a in data:
        fromArray.append(a.to_bytes(1, "big"))
    return fromArray

def fromListOfBytesToBytes(data: list):
    return b''.join(data)

def encript(data: bytes, password: bytes):
    data_array: list = bytesToIntArray(data)
    data_password_array: list = bytesToIntArray(password)
    data_array_encripted: list = []
    i = 0
    for x in data_array:
        data_array_encripted.append(((x + data_password_array[i]) % 256))
        i+=1
        if(i >= len(data_password_array)):
            i = 0
    return base64.encodebytes(fromListOfBytesToBytes(intBytesToCharBytes(data_array_encripted))).decode()

def encriptKeys(keyPair, password):
    if not 'publicKey' in keyPair or not 'secretKey' in keyPair:
        raise Exception("Invalid KeyPair: expected to find keys of name 'secretKey' and 'publicKey': " + json.dumps(keyPair))
    public_key: str = encript(str(keyPair["publicKey"]).encode(), password.encode())
    secret_key: str = encript(str(keyPair["secretKey"]).encode(), password.encode())
    return {"publicKey": public_key, "secretKey": secret_key}

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

def registro(usuario, password):
    keys: dict = genKeyPair()
    signed_user: dict = sign(usuario, keys)
    encriptedKeys: dict = encriptKeys(keys, password)
    write(json.dumps(signed_user), "public_key.cer")
    write(json.dumps(signed_user), "public_key.json")
    write(json.dumps(encriptedKeys), "private_key.cer")
    write(json.dumps(encriptedKeys), "private_key.json")

def main():
    usuario: str = input("Usuario > ")
    password: str = input("Contraseña > ")
    registro(usuario, password)
    return 0

if __name__ == "__main__":
    main()


