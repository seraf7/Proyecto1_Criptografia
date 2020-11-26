from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
#Importamos la función default_timer de la librería timeit, esta nos ayudará a
#tomar los tiempos de ejecución
from timeit import default_timer

#Se genera una llave aleatoria de 256 bits
#key = get_random_bytes(256)

#Funciones
def parametroAES_ECB(kAES):
	"""
	Genera el objeto AES en modo ECB
	kAES: llave que se usara para cifrar y descifrar
	cipher: objeto AES en modo ECB
	"""
	cipher = AES.new(kAES,AES.MODE_ECB)
	return cipher

def cifrarAES_ECB(plaintext):
	"""
	Cifra el texto en claro haciendo uso de AES-ECB
	plaintext: texto en claro a cifrar
	cyphertext: texto cifrado con AES-ECB
	"""
	cyphertext = cipher.encrypt(pad(plaintext,AES.block_size))
	return cyphertext

def descifrarAES_ECB(cyphertext):
	"""
	Descifra el cryptograma haciendo uso de AES-ECB
	cyphertext: cryptograma a descifrar
	msg: texto descifrado con AES-ECB
	"""
	msg = unpad(cipher.decrypt(cyphertext),AES.block_size)
	return msg

kAES = b'8d2e60365f17c7df1040d7501b4a7b5a'
pTextAES = b'59b5088e6dadc3ad5f27a460872d5929'

cipher = parametroAES_ECB(kAES)

t0 = default_timer() #Tomamos el tiempo en que inicia la ejecución del cifrado
cyphertext = cifrarAES_ECB(pTextAES)
t1 = default_timer() #Tomamos el tiempo en que termina la ejecución del cifrado
#Se imprime el tiempo total de ejecución del cifrado el cual es t1-t0
print("Tomo {} segundos cifrar con AES-ECB".format(t1-t0))
print(cyphertext.hex())

t0 = default_timer() #Tomamos el tiempo en que inicia la ejecución de descifrado
msg = descifrarAES_ECB(cyphertext)
t1 = default_timer() #Tomamos el tiempo en que termina la ejecución de descifrado
#Se imprime el tiempo total de ejecución de descifrado el cual es t1-t0
print("Tomo {} segundos descifrar con AES-ECB".format(t1-t0))
print(msg.decode())