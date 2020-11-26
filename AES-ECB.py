from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
#Importamos la función default_timer de la librería timeit, esta nos ayudará a
#tomar los tiempos de ejecución
from timeit import default_timer

#Llave de 256 bits
kAES = "0000000000000000000000000000000000000000000000000000000000000000"
kAES = bytes.fromhex(kAES)
#Mensaje en claro
pTextAES = "014730f80ac625fe84f026c60bfd547d"
pTextAES = bytes.fromhex(pTextAES)

#Objeto AES que servira para el cifrado y descifrado
cipher = AES.new(kAES, AES.MODE_ECB)
t0 = default_timer() #Tomamos el tiempo en que inicia la ejecución del cifrado
cyphertext = cipher.encrypt(pad(pTextAES,AES.block_size))
t1 = default_timer() #Tomamos el tiempo en que termina la ejecución del cifrado
print("Tomo {} segundos cifrar con AES-ECB".format(t1-t0))
print(cyphertext.hex())

t0 = default_timer() #Tomamos el tiempo en que inicia la ejecución del cifrado
msg = unpad(cipher.decrypt(cyphertext),AES.block_size)
t1 = default_timer() #Tomamos el tiempo en que termina la ejecución del cifrado
print("Tomo {} segundos descifrar con AES-ECB".format(t1-t0))
print(msg.hex())
