
import sys
import os 
#Biblioteca para las funciones HASH
import hashlib 
#Biblioteca para SHA-3	
if sys.version_info < (3, 6): 
    import sha3 
#Importamos la función default_timer de la librería timeit, esta nos ayudará a
#tomar los tiempos de ejcución
from timeit import default_timer


def sha3_512():
	#Generación de una cadena de bytes
	M="7c1688217b313278b9eae8edcf8aa4271614296d0c1e8916f9e0e940d28b88c5"
	M=bytes.fromhex(M)

	#Tomamos el tiempo en que inicia la ejecución del hash
	t0 = default_timer()
	#Creación objeto HASH
	sha3_512= hashlib.new("sha3_512", M) 
	#Tomamos el tiempo en que termina la ejecución del hash
	t1 = default_timer() 
	#Se imprime el tiempo total de ejecución del hash el cual es t1-t0
	print("Tomo {} segundos SHA-3 512".format(t1-t0))

	print(sha3_512.hexdigest())
	print(len(sha3_512.hexdigest()))


		
#ejecución 
sha3_512()

