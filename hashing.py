import sys
import os 
import pandas as pd
#Biblioteca para las funciones HASH
import hashlib 
#Biblioteca para SHA-3	
if sys.version_info < (3, 6): 
    import sha3 
#Algoritmos HASH
from Crypto.Hash import SHA3_384
#Importamos la función default_timer de la librería timeit, esta nos ayudará a
#tomar los tiempos de ejcución
from timeit import default_timer

##Algoritmo SHA2_384
def sha2_384(M):
	global t_SHA2_384
	# Generación de cadena 
	M=bytes.fromhex(M)
	#Tomamos el tiempo en que inicia la ejecución del hash
	t0 = default_timer()
	sha=hashlib.new('sha384')
	sha.update(M)
	#Tomamos el tiempo en que termina la ejecución del hash
	t1 = default_timer()
	t_SHA2_384.append("{0:0.10f}".format(t1-t0))


##Algoritmo SHA2_512
def sha2_512(M):
	global t_SHA2_512
	# Generación de cadena 
	M=bytes.fromhex(M)
	#Tomamos el tiempo en que inicia la ejecución del hash
	t0 = default_timer()
	# Uso de SHA512() 
	result = hashlib.sha512(M) 
	#Tomamos el tiempo en que termina la ejecución del hash
	t1 = default_timer()
	t_SHA2_512.append("{0:0.10f}".format(t1-t0))  

##Algoritmo SHA3_384
def sha3_384(M):
	#Generacion de una cadena de bytes
	M = bytes.fromhex(M)
	#Tomamos el tiempo en que inicia la ejecución del hash
	t0 = default_timer()
	#Creacion de objeto Hash
	h_obj = SHA3_384.new()
	#Generacion de hash
	h_obj.update(M)
	#Tomamos el tiempo en que termina la ejecución del hash
	t1 = default_timer()
	t_SHA3_384.append("{0:0.10f}".format(t1-t0))

##Algoritmo SHA3_512
def sha3_512(M):
	global t_SHA3_512
	#Generación de una cadena de bytes
	M=bytes.fromhex(M)
	#Tomamos el tiempo en que inicia la ejecución del hash
	t0 = default_timer()
	#Creación objeto HASH
	sha3_512= hashlib.new("sha3_512", M) 
	#Tomamos el tiempo en que termina la ejecución del hash
	t1 = default_timer() 
	#Se imprime el tiempo total de ejecución del hash el cual es t1-t0
	t_SHA3_512.append("{0:0.10f}".format(t1-t0))

def impresion():
	valores = {"Vectores": len_vectores,"SHA2_384": t_SHA2_384,"SHA2_512": t_SHA2_512, "SHA3_384": t_SHA3_384, "SHA3_512": t_SHA3_512}
	tabla = pd.DataFrame(valores)
	print(tabla)

def promedio(lista):
	global cont
	suma=0.0
	for valor in lista:
		suma+=float(valor)
	return "{0:0.10f}".format(float(suma/cont))

#Contador de vectores
cont=0

#Lista de todos los tiempos
t_SHA3_512=[]
t_SHA3_384=[]
t_SHA2_384=[]
t_SHA2_512=[]
len_vectores=[]

#Leer valor del vector de un archivo 
archivo = open('vectores_hash.txt','r')
for vector in archivo:
	##Si no es un comentario
	if(vector.strip('\n')[0]!='#'):
		if(vector.strip('\n')[0]=='L'):
			len_vectores.append(vector.strip("Len = ").strip('\n'))
		#Verifica si el tamaño del
		else:
			cont+=1
			sha2_384(vector.strip('\n'))
			sha2_512(vector.strip('\n'))
			sha3_384(vector.strip('\n'))
			sha3_512(vector.strip('\n'))
			



impresion()
print("\nPromedio SHA2_384: ",promedio(t_SHA2_384))
print("\nPromedio SHA2_512: ",promedio(t_SHA2_512))
print("\nPromedio SHA3_384: ",promedio(t_SHA3_384))
print("\nPromedio SHA3_512: ",promedio(t_SHA3_512))