#Criptografía 2021-1
#Primer Proyecto Parcial
#Castillo López Humberto Serafín
#García Racilla Sandra
#Sánchez Escobar Fernando
#Ejecuta todos los algoritmos

import sys
import os

print(sys.version_info)

####Instalación de Bibliotecas necesarias para el proyecto
#si no cuenta con alguno, descomente las líneas para su ejecución
#os.system('pip install pandas')
#os.system('pip install cryptography')
#os.system('pip install pycrypto')
#os.system('pip install matplotlib')

#Instalacion de bibliotecas en sistemas linux
#os.system('pip3 install pandas')
#os.system('pip3 install cryptography')
#os.system('pip3 install pycrypto')
#os.system('pip3 install matplotlib')

#Ejecucion para sistemas posix
if(os.name == "posix"):
    os.system('python3 cifrado_descifrado.py')
    os.system('python3 hashing.py')
    os.system('python3 sign_verify.py')
#Ejecucion para sistemas windows
elif(os.name == "nt"):
    os.system('python cifrado_descifrado.py')
    os.system('python hashing.py')
    os.system('python sign_verify.py')
