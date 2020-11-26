#Algoritmos HASH
from Crypto.Hash import SHA3_384

#Creacion de objeto Hash
h_obj = SHA3_384.new()

#Generacion de una cadena de bytes
Msg = "fb52"
Msg = bytes.fromhex(Msg)

#Generacion de hash
h_obj.update(Msg)

#Impresion del hash en hexadecimal
print(h_obj.hexdigest())
