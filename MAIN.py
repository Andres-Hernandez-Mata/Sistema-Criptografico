import base64
import pyfiglet as header
from termcolor import colored
from nacl.signing import SigningKey
#en las opciones agrego un comentario con la función y los parametros que se
#le deben mandar a esa función en específico

#para generar las llaves
def register(username: str, password: str):
    seed: bytes = genKeyPair()
    signed: dict = sign(username, seed)
    write(encrypt(seed, password.encode("utf-8")), "contraseña.key")
    print(signed)
    write(signed, "user.cer")

def genKeyPair():
    kp = SigningKey.generate()
    return kp._seed

def sign(msg: str, seed: bytes):
    sign_key = SigningKey(seed)
    signed_raw = sign_key.sign(msg.encode("utf-8"))
    return signed_raw

def write(data: bytes, path: str):
    with open(path, "wb") as file:
        file.write(data)   

    
def encrypt(data: bytes, password: bytes):
    encrypted_array: list = []
    i=0
    for d in data:
        encrypted_array.append(((d + password[i]) % 256).to_bytes(1, "big"))
        i+=1
        if i >= len(password):
            i=0
    return b''.join(encrypted_array)
 
#para verificar el login
def login(password: str):
    seed: bytes = decrypt(read("contraseña.key"), password.encode("utf-8"))
    signed_raw: bytes = read("user.cer")
    print(signed_raw)
    verify_key = SigningKey(seed).verify_key
    print(verify_key._key)
    try:        
        verify_key.verify(signed_raw)
        return True
    except BadSignatureError:
        return False
    
def decrypt(data: bytes, password: bytes):
    decrypted_array: list = []
    i=0
    for d in data:
        decrypted_array.append(((d - password[i]) % 256).to_bytes(1, "big"))
        i+=1
        if i >= len(password):
            i=0
    return b''.join(decrypted_array)

def read(path: bytes):
    with open(path, "rb") as file:
        return file.read()
    
#para ejecutar el menu
def main():
    while(True):
        banner = header.figlet_format("MENU PRINCIPAL")
        print(colored(banner.rstrip("\n"), "red", attrs=["bold"]))
        print(colored("Selecciona una opción: ", "blue", attrs=["bold"]))
        print(colored("[1]Login", "blue", attrs=["bold"]))
        print(colored("[2]Registro", "blue", attrs=["bold"]))
        print(colored("[3]salir", "blue", attrs=["bold"]))
        opc=int(input(colored("--->", "blue", attrs=["bold"])))
        #si se elige 1 manda al login
        if opc == 1:
            print('')
            passw=input((colored("ingresa la contraseña: ", "blue", attrs=["bold"])))
            #aqui se comprobaría la existencia del usuario
            login(passw)
            
        #si se elige 2 manda al registro
        if opc == 2:
            user=input((colored("ingresa El nombre de usuario: ", "blue", attrs=["bold"])))
            passw=input((colored("ingresa la contraseña: ", "blue", attrs=["bold"])))
            passwConf=input((colored("ingresa de nuevo la contraseña: ", "blue", attrs=["bold"])))
            #para verificar la contraseña
            while (passw != passwConf):
                 print(colored("las contraseñas no coinciden, ingresa nuevamente: ", "red", attrs=["bold"]))
                 user=input((colored("ingresa El nombre de usuario: ", "blue", attrs=["bold"])))
                 passw=input((colored("ingresa la contraseña: ", "blue", attrs=["bold"])))
                 passwConf=input((colored("ingresa de nuevo la contraseña: ", "blue", attrs=["bold"])))
            print(colored("listo!, usuario registrado exitosamente.", "green", attrs=["bold"]))
            register(user,passw)
            
        if opc <1 or opc>2:
            print(colored("Hasta luego!", "blue", attrs=["bold"]))
            break

if __name__ == "__main__":
    main()