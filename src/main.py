import base64
import pyfiglet as header
from termcolor import colored
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

def encrypt(data: bytes, password: bytes):
    encrypted_array: list = []
    i=0
    for d in data:
        encrypted_array.append(((d + password[i]) % 256).to_bytes(1, "big"))
        i+=1
        if i >= len(password):
            i=0
    return b''.join(encrypted_array)

def decrypt(data: bytes, password: bytes):
    decrypted_array: list = []
    i=0
    for d in data:
        decrypted_array.append(((d - password[i]) % 256).to_bytes(1, "big"))
        i+=1
        if i >= len(password):
            i=0
    return b''.join(decrypted_array)

def write(data: bytes, path: str):
    with open(path, "wb") as file:
        file.write(data)

def read(path: bytes):
    with open(path, "rb") as file:
        return file.read()

def genKeyPair():
    kp = SigningKey.generate()    
    return kp._seed

def bytesToString(data: bytes):
    return base64.encodebytes(data).decode("utf-8")

def stringToBytes(data: str):
    return base64.decodebytes(data.encode("utf-8"))

def sign(username: str, seed: bytes):
    sign_key = SigningKey(seed)
    signed_raw = sign_key.sign(username.encode("utf-8"))
    return signed_raw

def register(username: str, password: str):
    seed: bytes = genKeyPair()
    signed: dict = sign(username, seed)
    write(encrypt(seed, password.encode("utf-8")), "andres.key")
    #print(signed)
    write(signed, "andres.cer")

def login(password: str):
    seed: bytes = decrypt(read("andres.key"), password.encode("utf-8"))
    signed_raw: bytes = read("andres.cer")
    #print(signed_raw)
    verify_key = SigningKey(seed).verify_key
    #print(verify_key._key)
    try:        
        verify_key.verify(signed_raw)
        print(colored("El usuario es valido!", "green", attrs=["bold"]))
    except BadSignatureError:
        print(colored("El usuario no es valido!", "red", attrs=["bold"]))

def main():
    while(True):
        banner = header.figlet_format("Sistema Criptografico")
        print(colored(banner.rstrip("\n"), "red", attrs=["bold"]))        
        print(colored("[1] Login", "blue", attrs=["bold"]))
        print(colored("[2] Registro", "blue", attrs=["bold"]))
        print(colored("[3] Salir", "blue", attrs=["bold"]))
        opc = int(input(colored("[*] Selecciona una opción > ", "blue", attrs=["bold"])))
        #si se elige 1 manda al login
        if opc == 1:            
            passw = input((colored("\nIngresa la contraseña > ", "blue", attrs=["bold"])))
            #aqui se comprobaría la existencia del usuario
            login(passw)            
        #si se elige 2 manda al registro
        if opc == 2:
            user = input((colored("Ingresa el nombre de usuario > ", "blue", attrs=["bold"])))
            passw = input((colored("Ingresa la contraseña > ", "blue", attrs=["bold"])))
            passwConf = input((colored("Ingresa de nuevo la contraseña > ", "blue", attrs=["bold"])))
            #para verificar la contraseña
            while (passw != passwConf):
                print(colored("Las contraseñas no coinciden, ingresa nuevamente", "red", attrs=["bold"]))
                user = input((colored("Ingresa el nombre de usuario > ", "blue", attrs=["bold"])))
                passw = input((colored("Ingresa la contraseña > ", "blue", attrs=["bold"])))
                passwConf = input((colored("Ingresa de nuevo la contraseña > ", "blue", attrs=["bold"])))
            #print(colored("Listo!, usuario registrado exitosamente.", "green", attrs=["bold"]))
            register(user, passw)            
        if opc < 1 or opc > 2:
            print(colored("Hasta luego!", "blue", attrs=["bold"]))
            break

if __name__ == "__main__":
    main()