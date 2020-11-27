#Criptografía 2021-1
#Castillo López Humberto Serafín
#García Racilla Sandra
#Sánchez Escobar Fernando
#Ejecuta todos los algoritmos de cifrado y descifrado
#AES_CBC, AES_ECB, RSA_OAEP 
#Muestra la tabla de los tiempos de cada uno de los algoritmos por los vectores de prueba
#Además del promedio de tiempo
import pylab as pl
import sys
import os 
import pandas as pd
#Importamos la función default_timer de la librería timeit, esta nos ayudará a
#tomar los tiempos de ejcución
from timeit import default_timer
#Cifrador por bloques
import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#Bibliotecas cifrado RSA_OAEP
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA



def convBytes(m):
    cb = bytes.fromhex(m)
    return cb

def aes_cbc(PLAINTEXT):
	global c_aes_cbc
	global t_c_aes_cbc
	global t_d_aes_cbc
	KEY = "0000000000000000000000000000000000000000000000000000000000000000"
	KEY = convBytes(KEY)

	IV = "00000000000000000000000000000000"
	IV = convBytes(IV)

	PLAINTEXT = convBytes(PLAINTEXT)

	########Cifrado	
	#Tomamos el tiempo en que inicia la ejecución del cifrado
	t0 = default_timer()
	#Creacion del cifrador
	cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
	#Cirfado de una cadena de bytes, usa proceso de padding en el mensaje
	ct_bytes = cipher.encrypt(pad(PLAINTEXT, AES.block_size))
	#Tomamos el tiempo en que termina la ejecución del cifrado
	t1 = default_timer() 
	#Se imprime el tiempo total de ejecución del cifrado el cual es t1-t0
	t_c_aes_cbc.append("{0:0.10f}".format(t1-t0))

	h = ct_bytes.hex()
	#Guardamos el valor de cifrado para el texto en claro
	c_aes_cbc.append(len(h))

	########Descifrado
	#Tomamos el tiempo en que inicia la ejecución del descifrado
	t0 = default_timer()
	#Objeto para descifrar el mensaje
	descipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
	#Proceso de descifrado, también se remueve el padding del mensaje
	msj = unpad(descipher.decrypt(ct_bytes), AES.block_size)
	#Tomamos el tiempo en que termina la ejecución del descifrado
	t1 = default_timer() 
	#Se imprime el tiempo total de ejecución del descifrado el cual es t1-t0
	t_d_aes_cbc.append("{0:0.10f}".format(t1-t0))


#Algoritmo AES_ECB
def aes_ecb(pTextAES):
	global c_aes_ecb	
	global t_c_aes_ecb	
	global t_d_aes_ecb
	#Inicializamos llave de 256 bits
	kAES = "0000000000000000000000000000000000000000000000000000000000000000"
	kAES = bytes.fromhex(kAES)
	#Mensaje en claro
	pTextAES = bytes.fromhex(pTextAES)

	######Cifrado
	#Tomamos el tiempo en que inicia la ejecución del cifrado
	t0 = default_timer()
	#Objeto AES que servira para el cifrado y descifrado
	cipher = AES.new(kAES, AES.MODE_ECB)
	cyphertext = cipher.encrypt(pad(pTextAES,AES.block_size))
	#Tomamos el tiempo en que termina la ejecución del cifrado
	t1 = default_timer() 
	#Se imprime el tiempo total de ejecución del cifrado el cual es t1-t0
	t_c_aes_ecb.append("{0:0.10f}".format(t1-t0))

	
	c_aes_ecb.append(len(cyphertext.hex()))

	#####Descifrado
	#Tomamos el tiempo en que inicia la ejecución del cifrado
	t0 = default_timer() 
	#Objeto AES que servira para el cifrado y descifrado
	cipher2 = AES.new(kAES, AES.MODE_ECB)
	msg = unpad(cipher2.decrypt(cyphertext),AES.block_size)
	#Tomamos el tiempo en que termina la ejecución del cifrado
	t1 = default_timer() 
	#Se imprime el tiempo total de ejecución del descifrado el cual es t1-t0
	t_d_aes_ecb.append("{0:0.10f}".format(t1-t0))


#Algoritmo RSA_OAEP
def rsa_oaep(message):
	global c_rsa_oaep	
	global t_c_rsa_oaep	
	global t_d_rsa_oaep
	#Damos formato a mensaje
	message	= bytes.fromhex(message)
	#Valores de la llaves
	n=int("9195E9854FA04A1433D4E22048951426A0ACFC6FE446730579D742CAEA5FDF6590FAEC7F71F3EBF0C6408564987D07E19EC07BC0F601B5E6ADB28D9AA6148FCC51CFF393178983790CC616C0EF34AB50DC8444F44E24117B46A47FA3630BF7E696865BFC245F7C3A314CD48C583D7B2223AF06881158557E37B3CC370AE6C8D5",16)
	e=int("010001",16)
	d=int("05B2DDE134ACB6E448E31C618720796EC9A5FBD0FAC3DC876A5832BFC94CD76C725B0AC6DCFF09F7F2CAB3C356F4B89F96F1E73B8BBAFABE7CD8C5BCE2A360BD8A3CE2767A2F83A6B143C2446D5A0388748F91813BB5E7A6CEA402368842DBC50C11EFE6B26CB08B53B83BC7FB17D5A62C39A6CCC718165D59375BE387642601",16)
	np2=int("CCF876B8B473F7E05C9551EE3F7ECA0C57CB542E0849B663026CB8A2896E75B80CC6D2415425DD5987ECB47AE7DCD091BA3F609B0FE02E969C4E7DC29E36437D",16)
	np1=int("B5D49FA4F78255C12DD125EF76EB039DA81CECF80C314E1E067706E200101117EF3D03479EEC26DBFA7355CD2913F3AD7F465D6F1424D8A8506A1E8852606A39",16)
	coef=int("036F02D351D7831238E5361BAC0D60888D0F2AB38B0DED7A14A90E2CF1D4D3BD72395F9667ED279889987808288FFF2739927A2868F01A3036BD85D44DDA9FD5",16)
	
	###Cifrado
	#Tomamos el tiempo en que inicia la ejecución del cifrado
	#RSA.construct(n,e,d,n(p)1,n(p)2,coef)
	key_object=RSA.construct((n,e,d,np1,np2,coef),consistency_check=True)
	t0 = default_timer()
	#Creación objeto de llave RSA
	cipher = PKCS1_OAEP.new(key_object)
	ciphertext = cipher.encrypt(message) 
	#Tomamos el tiempo en que termina la ejecución del cifrado
	t1 = default_timer() 
	#Se imprime el tiempo total de ejecución del cifrado el cual es t1-t0
	t_c_rsa_oaep.append("{0:0.10f}".format(t1-t0))

	h=ciphertext.hex()
	c_rsa_oaep.append(len(h))


	###Descifrado
	#RSA.construct(n,e,d,n(p)1,n(p)2,coef)
	key_object2 = RSA.construct((n,e,d,np1,np2,coef),consistency_check=True)
	#Tomamos el tiempo en que inicia la ejecución del descifrado
	t0 = default_timer()
	#Creación objeto de llave RSA
	cipher = PKCS1_OAEP.new(key_object2)
	message = cipher.decrypt(ciphertext)
	#Tomamos el tiempo en que termina la ejecución del descifrado
	t1 = default_timer() 
	#Se imprime el tiempo total de ejecución del descifrado el cual es t1-t0
	t_d_rsa_oaep.append("{0:0.10f}".format(t1-t0))



#Función impresión tabla
def impresion(vector,t_cbc,t_ecb,t_rsa):
	valores = {"Vectores": vector,"AES_CBC": t_cbc,"AES_ECB": t_ecb, "RSA_OAEP": t_rsa}
	tabla = pd.DataFrame(valores)
    #Imprimir tabla completa
	pd.set_option('display.max_rows', None, 'display.max_columns', None)
	print(tabla)

def promedio(lista):
	global cont
	suma=0.0
	for valor in lista:
		suma+=float(valor)
	return "{0:0.10f}".format(float(suma/cont))

#Calcular promedios por tamaño
def promedioTamano(tam, tiempo):
	cont = [0, 0, 0, 0]
	suma = [0, 0, 0, 0]
	for i in range(len(tam)):
		
		if tam[i] == 512:
			agregar(tiempo[i], 3, cont, suma)
		elif tam[i] == 384:
			agregar(tiempo[i], 2, cont, suma)
		elif tam[i] == 256:
			agregar(tiempo[i], 1, cont, suma)
		elif tam[i] == 64:
			agregar(tiempo[i], 0, cont, suma)
	for i in range(len(suma)):
		suma[i] = suma[i] / cont[i]
	return suma

def agregar(v, i, cont, suma):
	cont[i] += 1
	suma[i] += float(v)


#Contador de vectores
cont=0

#lista cifrados
c_aes_cbc=[]
c_aes_ecb=[]
c_rsa_oaep=[]

#Lista de todos los tiempos
t_c_aes_cbc=[]	#Cifrado
t_d_aes_cbc=[]	#Descifrado
t_c_aes_ecb=[]	#Cifrado
t_d_aes_ecb=[]	#Descifrado
t_c_rsa_oaep=[]	#Cifrado
t_d_rsa_oaep=[]	#Descifrado
#Tamaño de los vectores de prueba
vectores=[]

#Leer valor del vector de un archivo 
archivo = open('vectores_cifrado_descifrado.txt','r')
for vector in archivo:
	##Si no es un comentario
	if(vector.strip('\n')[0]!='#'):
		cont+=1
		vectores.append(len(vector.strip("plain = ").strip('\n'))*4)
		aes_cbc(vector.strip("plain = ").strip('\n'))
		aes_ecb(vector.strip("plain = ").strip('\n'))
		rsa_oaep(vector.strip("plain = ").strip('\n'))
archivo.close()


#Guardar salida original
oldstdout = sys.stdout
#Crear y abrir archivo
f = open('Cifrado.txt', 'w')
#Redirigir la salida estandar
sys.stdout = f

#Impresión tabla cifrado
impresion(vectores,t_c_aes_cbc,t_c_aes_ecb,t_c_rsa_oaep)
print("\nPromedio AES_CBC: ",promedio(t_c_aes_cbc))
print("\nPromedio AES_ECB: ",promedio(t_c_aes_ecb))
print("\nPromedio RSA_OAEP: ",promedio(t_c_rsa_oaep))

#vaciar el buffer de salida
sys.stdout.flush()
#Cerrar archivo y volver salida original
f.close()
sys.stdout = oldstdout

#Graficar resultados
pl.figure(1)
pl.plot([64, 256, 384, 512], promedioTamano(vectores, t_c_aes_cbc), label='AES-CBC')
pl.plot([64, 256, 384, 512], promedioTamano(vectores, t_c_aes_ecb), label='AES-ECB')
pl.plot([64, 256, 384, 512], promedioTamano(vectores, t_c_rsa_oaep), label='RSA-OAEP')
pl.xlabel("Tamaño del mensaje")
pl.ylabel("Tiempo de procesamiento")
pl.title("Funciones cifrado")
pl.legend()
#Guardar grafico con los resultados
pl.savefig("Cifrado.png")

print("Se han generado los resultados de los algoritmos de Cifrado")

#Guardar salida original
oldstdout = sys.stdout
#Crear y abrir archivo
f = open('Descifrado.txt', 'w')
#Redirigir la salida estandar
sys.stdout = f

#Impresión tabla descifrado
impresion(vectores,t_d_aes_cbc,t_d_aes_ecb,t_d_rsa_oaep)
print("\nPromedio AES_CBC: ",promedio(t_d_aes_cbc))
print("\nPromedio AES_ECB: ",promedio(t_d_aes_ecb))
print("\nPromedio RSA_OAEP: ",promedio(t_d_rsa_oaep))
#vaciar el buffer de salida
sys.stdout.flush()
#Cerrar archivo y volver salida original
f.close()
sys.stdout = oldstdout

pl.figure(2)
#Graficar resultados
pl.plot([64, 256, 384, 512], promedioTamano(vectores, t_d_aes_cbc), label='AES-CBC')
pl.plot([64, 256, 384, 512], promedioTamano(vectores, t_d_aes_ecb), label='AES-ECB')
pl.plot([64, 256, 384, 512], promedioTamano(vectores, t_d_rsa_oaep), label='RSA-OAEP')
pl.ylabel("Tiempo de procesamiento")
pl.title("Funciones descifrado")
pl.legend()
#Guardar grafico con los resultados
pl.savefig("Descifrado.png")
print("Se han generado los resultados de los algoritmos de Descifrado")