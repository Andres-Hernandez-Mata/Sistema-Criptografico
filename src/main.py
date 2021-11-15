import os
import pyfiglet as header
from termcolor import colored
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

clear = lambda: os.system("cls" if os.name=="nt" else "clear")

def encrypt(data: bytes, password: bytes):
    encrypted_array: list = []
    i = 0
    for d in data:
        encrypted_array.append(((d + password[i]) % 256).to_bytes(1, "big"))
        i+=1
        if i >= len(password):
            i = 0    
    return b''.join(encrypted_array)

def decrypt(data: bytes, password: bytes):
    try:
        decrypted_array: list = []
        i=0
        for d in data:
            decrypted_array.append(((d - password[i]) % 256).to_bytes(1, "big"))
            i+=1
            if i >= len(password):
                i = 0        
        return b''.join(decrypted_array)
    except Exception:
        pass

def write(data: bytes, path: str):
    with open(path, "wb") as file:
        file.write(data)    

def read(path: bytes):
    try:
        with open(path, "rb") as file:
            return file.read()
    except FileNotFoundError:        
        print(colored("No existe el archivo ingresado, %s" % path, "red", attrs=["bold"]))
        exit()

def genKeyPair():
    kp = SigningKey.generate()    
    return kp._seed

def sign(username: str, seed: bytes):
    sign_key = SigningKey(seed)
    signed_raw = sign_key.sign(username.encode("utf-8"))
    return signed_raw

def register(username: str, password: str):
    seed: bytes = genKeyPair()
    signed: dict = sign(username, seed)
    write(encrypt(seed, password.encode("utf-8")), "{}.key".format(username))    
    write(signed, "{}.cer".format(username))
    print(colored("Se registro el usuario %s al sistema criptografico" % username, "green", attrs=["bold"]))
    print(colored("Se genero el certificado y la llave privada", "green", attrs=["bold"]))

def login(privada: bytes, certificado: bytes, password: str):
    global valor
    #Se usa para cifrar el resultado del cifrado césar
    global contra_ces
    seed: bytes = decrypt(read(privada), password.encode("utf-8"))
    signed_raw: bytes = read(certificado)    
    verify_key = SigningKey(seed).verify_key    
    try:
        verify_key.verify(signed_raw)        
        print(colored("Bienvenido al sistema de mensajería!", "green", attrs=["bold"]))
        contra_ces = password.encode("utf-8")
        valor = True
    except BadSignatureError:
        print(colored("La contraseña es incorrecta!", "red", attrs=["bold"]))
        valor = False

#Una vez validado el usuario muestra el siguiente menú
def opc_log(val):
    while(val == True):
        banner = header.figlet_format("Mensajeria")
        print(colored(banner.rstrip("\n"), "red", attrs=["bold"]))        
        print(colored("[1] Cifrar mensaje", "blue", attrs=["bold"]))
        print(colored("[2] Descifrar mensaje", "blue", attrs=["bold"]))
        print(colored("[3] Cerrar sesión", "blue", attrs=["bold"]))
        eleccion = int(input(colored("[*] Selecciona una opción > ", "blue", attrs=["bold"])))
        if eleccion == 1:   
            print(colored("AVISO, este mensaje estará cifrado por cesar!", "red", attrs=["bold"]))
            mensaje = input(colored("Escribe tu mensaje > ", "blue", attrs=["bold"]))
            #Se envia el mensaje y la llave para encriptar
            enc_msj(mensaje, 3)
        elif eleccion == 2:
            print(colored("Sugerencia: copia y pega abajo el mensaje encriptado", "red", attrs=["bold"]))
            decode = input(colored("Ingresa el mensaje encriptado > ", "blue", attrs=["bold"]))
            desenc_msj(decode, 3)
        elif eleccion < 1 or eleccion > 2:
            val = False

#Para encriptar el mensaje   
def enc_msj(mensaje, llave_cesar):  
    global simbolos
    simbolos = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
    resultado = ""
    for simbolo in mensaje:
        if simbolo in simbolos:
            indiceSimbolo = simbolos.find(simbolo)
            indiceNuevo = indiceSimbolo + llave_cesar
            if indiceNuevo >= len(simbolos):
                indiceNuevo = indiceNuevo - len(simbolos)
            elif indiceNuevo < 0:
                indiceNuevo = indiceNuevo + len(simbolos)
            resultado = resultado + simbolos[indiceNuevo]
        else:
            resultado = resultado + simbolo
    print(colored("Mensaje encriptado > {}\nApúntalo, se genero el archivo cifrado.txt".format(resultado), "green", attrs=["bold"]))
    #Encripta el resultado después de cifrarlo con césar
    write(encrypt(resultado.encode("utf-8"), contra_ces), "cifrado.txt")

#Para desencriptar el mensaje   
def desenc_msj(mensaje, llave_cesar): 
    resultado = ""
    for simbolo2 in mensaje:
        if simbolo2 in simbolos:
            indiceSimbolo = simbolos.find(simbolo2)
            indiceNuevo = indiceSimbolo - llave_cesar
            if indiceNuevo >= len(simbolos):
                indiceNuevo = indiceNuevo - len(simbolos)
            elif indiceNuevo < 0:
                indiceNuevo = indiceNuevo + len(simbolos)
            resultado = resultado + simbolos[indiceNuevo]
        else:
            resultado = resultado + simbolo2
    print(colored("Mensaje desencriptado > " + resultado, "green", attrs=["bold"]))

def main():
    while(True):
        banner = header.figlet_format("Sistema Criptografico")
        print(colored(banner.rstrip("\n"), "red", attrs=["bold"]))        
        print(colored("[1] Login", "blue", attrs=["bold"]))
        print(colored("[2] Registro", "blue", attrs=["bold"]))
        print(colored("[3] Limpiar", "blue", attrs=["bold"]))
        print(colored("[4] Salir", "blue", attrs=["bold"]))
        opc = int(input(colored("[*] Selecciona una opción > ", "blue", attrs=["bold"])))
        #Si se elige 1 manda al login
        if opc == 1:            
            while(True):
                certificado: bytes = input((colored("Certificado (.cer) > ", "blue", attrs=["bold"])))
                privada: bytes = input((colored("Clave privada (.key) > ", "blue", attrs=["bold"])))
                password = input((colored("Contraseña de la clave privada > ", "blue", attrs=["bold"])))
                if not certificado or not privada or not password:
                    print(colored("El certificado, clave privada y contraseña son datos obligatorios!", "red", attrs=["bold"]))
                else:
                    #Aqui se comprobaría la existencia del usuario
                    login(privada, certificado, password)
                    break
            #Le mando el valor que se obtiene al validar el usuario
            opc_log(valor)
        #Si se elige 2 manda al registro
        if opc == 2:            
            #Para verificar los datos ingresados
            while(True):
                user = input((colored("Ingresa el nombre del usuario > ", "blue", attrs=["bold"])))
                password = input((colored("Ingresa la contraseña > ", "blue", attrs=["bold"])))
                if not user or not password:
                    print(colored("El nombre del usuario y la contraseña son datos obligatorios!", "red", attrs=["bold"]))
                else:
                    register(user, password)
                    break
        if opc == 3:
            clear()
        if opc < 1 or opc > 3:
            print(colored("Hasta luego!", "blue", attrs=["bold"]))
            return False

if __name__ == "__main__":
    main()