import hashlib
from timeit import default_timer

#t0 = default_timer() #Tomamos el tiempo en que inicia la ejecución del cifrado
#cryptogram = hashlib.sha384(b'').hexdigest() -> Forma corta

def creaSHA2_384():
	return hashlib.new('sha384')

def SHA2_384(sha, ptxt_SHA384):
	sha.update(ptxt_SHA384)
	return sha.hexdigest()

ptxt_SHA384 = b'a'
sha = creaSHA2_384()
t0 = default_timer() #Tomamos el tiempo en que inicia la ejecución del cifrado
cryptogram = SHA2_384(sha, ptxt_SHA384)
t1 = default_timer() #Tomamos el tiempo en que termina la ejecución del cifrado
print("Tomo {} segundos realizar el hashing con SHA-2 384".format(t1-t0))
print(cryptogram)