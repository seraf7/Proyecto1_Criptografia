from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography import exceptions

#Se crea la curva eleiptica sobre el campo primo 
ECC = ec.SECP521R1()

#Variable que servira para generar la llave secreta
pValue = "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
pValue = int(pValue,16)
#Puntos a usar de la curva
# Coordenada x
pUx = "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
pUx = int(pUx,16)
# Coordenada y
pUy = "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
pUy = int(pUy,16)

msg = b"sample"

#Se genera la llave publica
pubK = ec.EllipticCurvePublicNumbers(x=pUx, y=pUy, curve=ECC)
pubKey = pubK.public_key()

#Se genera la llave privada
privK = ec.EllipticCurvePrivateNumbers(private_value=pValue, public_numbers=pubK)
privKey = privK.private_key()

#Hashing, en caso de que el mensaje sea demasiado largo
#hashing = hashes.Hash(hashes.SHA1())
#hashing.update(b"sample")
#digest = hashing.finalize()

#Se hace la firma
leFigme = privKey.sign(data=msg, signature_algorithm=ec.ECDSA(hashes.SHA1()))
ds = utils.decode_dss_signature(leFigme)
print("r = {}".format(hex(ds[0])))
print("s = {}".format(hex(ds[1])))

#Verificación de la firma
try:
	pubKey.verify(signature=leFigme, data=msg, signature_algorithm=ec.ECDSA(hashes.SHA1()))
	print("La firma es valida")
except(exceptions.InvalidSignature):
	print("Firma valida")
