import os
import base64
import pyfiglet as header
from termcolor import colored
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

clear = lambda: os.system("cls" if os.name=="nt" else "clear")

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
    global valor
    seed: bytes = decrypt(read("andres.key"), password.encode("utf-8"))
    signed_raw: bytes = read("andres.cer")
    #print(signed_raw)
    verify_key = SigningKey(seed).verify_key
    #print(verify_key._key)
    try:        
        verify_key.verify(signed_raw)        
        print(colored("El usuario es valido!", "green", attrs=["bold"]))
        valor = True
    except BadSignatureError:
        print(colored("El usuario no es valido!", "red", attrs=["bold"]))
        valor = False

#una vez validado el usuario muestra el siguiente menú
def opc_log(val):
    while(val == True):
        banner = header.figlet_format("Mensajeria")
        print(colored(banner.rstrip("\n"), "red", attrs=["bold"]))
        print(colored("Bienvenido al sistema de mensajería!", "blue", attrs=["bold"]))        
        print(colored("[1] Cifrar mensaje", "blue", attrs=["bold"]))
        print(colored("[2] Descifrar mensaje", "blue", attrs=["bold"]))
        print(colored("[3] Cerrar sesión", "blue", attrs=["bold"]))
        eleccion = int(input(colored("[*] Selecciona una opción > ", "blue", attrs=["bold"])))
        if eleccion == 1:   
            print(colored("AVISO, este mensaje estará cifrado por cesar!", "red", attrs=["bold"]))
            mensaje = input(colored("Escribe tu mensaje > ", "blue", attrs=["bold"]))
            #se envia el mensaje y la llave para encriptar
            enc_msj(mensaje, 3)
        elif eleccion == 2:
            print(colored("Sugerencia: copia y pega abajo el mensaje encriptado", "red", attrs=["bold"]))
            decode = input(colored("Ingresa el mensaje encriptado > ", "blue", attrs=["bold"]))
            desenc_msj(decode, 3)
        elif eleccion < 1 or eleccion > 2:
            val = False

#para encriptar el mensaje   
def enc_msj(mensaje, llave_cesar):  
    global SIMBOLOS
    SIMBOLOS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
    resultado = ''
    for simbolo in mensaje:
        if simbolo in SIMBOLOS:
            indiceSimbolo = SIMBOLOS.find(simbolo)
            indiceNuevo = indiceSimbolo + llave_cesar
            if indiceNuevo >= len(SIMBOLOS):
                indiceNuevo = indiceNuevo - len(SIMBOLOS)
            elif indiceNuevo < 0:
                indiceNuevo = indiceNuevo + len(SIMBOLOS)
            resultado = resultado + SIMBOLOS[indiceNuevo]
        else:
            resultado = resultado + simbolo
    print(colored("Mensaje encriptado > " + resultado +'\n' + "apúntalo!", "red", attrs=["bold"]))

#para desencriptar el mensaje   
def desenc_msj(mensaje, llave_cesar): 
    resultado = ''
    for simbolo2 in mensaje:
        if simbolo2 in SIMBOLOS:
            indiceSimbolo = SIMBOLOS.find(simbolo2)
            indiceNuevo = indiceSimbolo - llave_cesar
            if indiceNuevo >= len(SIMBOLOS):
                indiceNuevo = indiceNuevo - len(SIMBOLOS)
            elif indiceNuevo < 0:
                indiceNuevo = indiceNuevo + len(SIMBOLOS)
            resultado = resultado + SIMBOLOS[indiceNuevo]
        else:
            resultado = resultado + simbolo2
    print(colored("Mensaje desencriptado > " + resultado, "red", attrs=["bold"]))

def main():
    while(True):
        banner = header.figlet_format("Sistema Criptografico")
        print(colored(banner.rstrip("\n"), "red", attrs=["bold"]))        
        print(colored("[1] Login", "blue", attrs=["bold"]))
        print(colored("[2] Registro", "blue", attrs=["bold"]))
        print(colored("[3] Limpiar", "blue", attrs=["bold"]))
        print(colored("[4] Salir", "blue", attrs=["bold"]))
        opc = int(input(colored("[*] Selecciona una opción > ", "blue", attrs=["bold"])))
        #si se elige 1 manda al login
        if opc == 1:            
            passw = input((colored("Ingresa la contraseña > ", "blue", attrs=["bold"])))
            #aqui se comprobaría la existencia del usuario
            login(passw) 
            #le mando el valor que se obtiene al validar el usuario
            opc_log(valor)            
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
        if opc == 3:
            clear()
        if opc < 1 or opc > 3:
            print(colored("Hasta luego!", "blue", attrs=["bold"]))
            break

if __name__ == "__main__":
    main()