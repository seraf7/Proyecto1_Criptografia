
import sys 
#Biblioteca para las funciones HASH
import hashlib 
#Biblioteca para SHA-3	
if sys.version_info < (3, 6): 
    import sha3 
  
# Generación de cadena 
M = "664ef2e3a7059daf1c58caf52008c5227e85cdcb83b4c59457f02c508d4f4f69f826bd82c0cffc5cb6a97af6e561c6f96970005285e58f21ef6511d26e709889a7e513c434c90a3cf7448f0caeec7114c747b2a0758a3b4503a7cf0c69873ed31d94dbef2b7b2f168830ef7da3322c3d3e10cafb7c2c33c83bbf4c46a31da90cff3bfd4ccc6ed4b310758491eeba603a76"
print(type(M))
M=bytes.fromhex(M)
#Valor de vector de prueba  
salida="42BC8579EDB78B98EDCCD0258D701982EDA188B2C1F1F8109608CFD7235EF87F265EC4323F17433716C0B092AFCB30575CFFF4086F4EDED11EE44CE2ECB5474D"

# encoding GeeksforGeeks using encode() 
# then sending to SHA512() 
result = hashlib.sha512(M) 
  
# printing the equivalent hexadecimal value. 
print(result.hexdigest().upper())
print(len(result.hexdigest().upper()))

if (salida==result.hexdigest().upper()):
	print("Vas por el buen camino")
else:
	print("Algo hiciste mal")
