#Algoritmo de firma digital
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions

#Instancia de la curva NIST K-571
E = ec.SECT571K1()

#Valor escalar secreto
d = "0C16F58550D824ED7B95569D4445375D3A490BC7E0194C41A39DEB732C29396CDF1D66DE02DD1460A816606F3BEC0F32202C7BD18A32D87506466AA92032F1314ED7B19762B0D22"
d = int(d, 16)
#Punto X publico
Ux = "6CFB0DF7541CDD4C41EF319EA88E849EFC8605D97779148082EC991C463ED32319596F9FDF4779C17CAF20EFD9BEB57E9F4ED55BFC52A2FA15CA23BC62B7BF019DB59793DD77318"
Ux = int(Ux, 16)
#Punto Y publico
Uy = "1CFC91102F7759A561BD8D5B51AAAEEC7F40E659D67870361990D6DE29F6B4F7E18AE13BDE5EA5C1F77B23D676F44050C9DBFCCDD7B3756328DDA059779AAE8446FC5158A75C227"
Uy = int(Uy, 16)

#Mensaje
m = "sample"
m = bytes(m, 'utf-8')
#Alternativa de conversion, para mensajes hexadecimales
#m = bytes.fromhex(m)

#Generacion de la llave publica
pubs = ec.EllipticCurvePublicNumbers(x=Ux, y=Uy, curve=E)
kPub = pubs.public_key()
#print(kPub)

#Generacion de la llave privada
k = ec.EllipticCurvePrivateNumbers(private_value=d, public_numbers=pubs)
kPr = k.private_key()
#print(kPr)

#Generador de hash SHA-1
h = hashes.Hash(hashes.SHA1())

#Generacion de la firma
s = kPr.sign(data=m, signature_algorithm=ec.ECDSA(hashes.SHA1()))
ds = utils.decode_dss_signature(s)
print("r = ", hex(ds[0]))
print("s = ", hex(ds[1]))

#Mensaje
#m = "sampleasas"
#m = bytes(m, 'utf-8')

#Verificacion de la firma
try:
    #Uso de la llave publica para verificar
    kPub.verify(signature=s, data=m, signature_algorithm=ec.ECDSA(hashes.SHA1()))
    print("Firma valida")
except(exceptions.InvalidSignature):
    print("Firma no valida")
