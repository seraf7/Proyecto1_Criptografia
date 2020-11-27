#Criptografía 2021-1
#Castillo López Humberto Serafín
#García Racilla Sandra
#Sánchez Escobar Fernando
#Ejecuta todos los algoritmos de firma y verificación
#RSA-PSS, DSA, ECDSA Prime Field, ECDSA Binary Field
#Muestra la tabla de los tiempos de cada uno de los algoritmos por los vectores de prueba
#Además del promedio de tiempo
import pylab as pl
import sys
import os
import pandas as pd
#Importamos la función default_timer de la librería timeit, esta nos ayudará a
#tomar los tiempos de ejcución
from timeit import default_timer
#Algoritmo de firma digital
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
#Bibliotecas DSA
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
#Algoritmo de firma digital
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions


def rsa_pps(m):
	global t_s_rsa_pps
	global t_v_rsa_pps
	#Definicion de componentes para llave RSA
	#Modulo n
	n = "C4877F32540FCB427C7E875009D31000E6DC9C6B8BE6D56AE004E8909FBF379CA25D440516477E606F1C7B6C9F0BD1A10032C05811B4F7D4DEA576D3BC4EB5BB64808D561863E6CEA285B6F5D1FC465A37C18AC0F80FDBB1E686088BA661E17527EAE81147123F2314E2B9AD5AA546526C8126138139AAABFF716D900A7E32E7"
	n = int(n, 16)
	#Exponente publico e
	e = "010001"
	e = int(e, 16)
	#Exponente privado d, solo para llave privada
	d = "0586116B26B5B2EED174F4F4A8F207B71EC600977D3D25AE75516DFFF29D7B40A9C7994BD34E7B1CD6C2A42D6F62F3A764CC085FF14F76CFC2DA3FB6BFCA2E8D63161AE6A165E3A5EC5C5F354B71244C2BE5CD96234235AE4F0A5E3904D75D569743418B5CEB5D9CF9746E56BC543CCF115B3451D6414C16A470D62081EFE731"
	d = int(d, 16)
	#Primer factor primo np
	np = "FE835D94A2A7B98226BAA644EA61596469C446FFE1CBE627EF38862141C5FE263ADBFC9D595EC4F0032CE8FB36FF6829EF8431D7DD488C26DB497C29627F7FA3"
	np = int(np, 16)
	#Segundo factor primo nq
	nq = "C5AD6A065A251996F9AAE1C328DD64DB17EE0C72DCF52A8E97501D0BBD397730445BCD58E6EDC6501B3E5257276772681E2A959510302B0960447E6AD11363ED"
	nq = int(nq, 16)
	#Coeficiente q
	q = "B85E28968D974B9574EB0A0FB5087E866910B3B6A1BF219EB64001986FB6A6F5FA15BD3042FADD24B4E005D858799E45427D3A5CA4D4C269FDF11D57CA2D7BCD"
	q = int(q, 16)

	#Tupla de los componentes
	comp = (n, e, d, nq, np, q)

	#Mensaje
	m = bytes.fromhex(m)
	##Signing
	#Generacion de llave privada
	kp = RSA.construct(comp, consistency_check=True)
	#Tomamos el tiempo en que inicia la ejecución de la firma
	t0 = default_timer()
	#Generacion del hash
	h = SHA256.new(m)
	#Mensaje firmado
	s = pss.new(kp).sign(h)
	#Tomamos el tiempo en que termina la ejecución de la firma
	t1 = default_timer()
	#Se imprime el tiempo total de ejecución de la firma el cual es t1-t0
	t_s_rsa_pps.append("{0:0.10f}".format(t1-t0))


	#Generacion de llave privada
	kp2 = RSA.construct(comp, consistency_check=True)
	#Verificacion del mensaje
	#Tomamos el tiempo en que inicia la ejecución de la verificación
	t0 = default_timer()
	#Generacion del hash
	hr = SHA256.new(m)
	#Objeto verificador
	verifier = pss.new(kp2)
	try:
	    verifier.verify(hr, s)
	    #print("La firma es autentica")
	except(ValueError, TypeError):
	   #print("La firma no es autentica")
	   pass
	#Tomamos el tiempo en que termina la ejecución de la verificación
	t1 = default_timer()
	#Se imprime el tiempo total de ejecución de la verificación el cual es t1-t0
	t_v_rsa_pps.append("{0:0.10f}".format(t1-t0))

def dsa(message):
	global t_s_dsa
	global t_v_dsa
	#Inicializamos valores de llaves
	p=int("a8f9cd201e5e35d892f85f80e4db2599a5676a3b1d4f190330ed3256b26d0e80a0e49a8fffaaad2a24f472d2573241d4d6d6c7480c80b4c67bb4479c15ada7ea8424d2502fa01472e760241713dab025ae1b02e1703a1435f62ddf4ee4c1b664066eb22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5b06439ac9c7e9d8bde283",16)
	q=int("f85f0f83ac4df7ea0cdf8f469bfeeaea14156495",16)
	g=int("2b3152ff6c62f14622b8f48e59f8af46883b38e79b8c74deeae9df131f8b856e3ad6c8455dab87cc0da8ac973417ce4f7878557d6cdf40b35b4a0ca3eb310c6a95d68ce284ad4e25ea28591611ee08b8444bd64b25f3f7c572410ddfb39cc728b9c936f85f419129869929cdb909a6a3a99bbe089216368171bd0ba81de4fe33",16)
	x=int("c53eae6d45323164c7d07af5715703744a63fc3a",16)
	y=int("313fd9ebca91574e1c2eebe1517c57e0c21b0209872140c5328761bbb2450b33f1b18b409ce9ab7c4cd8fda3391e8e34868357c199e16a6b2eba06d6749def791d79e95d3a4d09b24c392ad89dbf100995ae19c01062056bb14bce005e8731efde175f95b975089bdcdaea562b32786d96f5a31aedf75364008ad4fffebb970b",16)

	#Mensaje
	message = bytes.fromhex(message)
	##Signing
	#Creación de un objeto de llave DSA
	#Crypto.PublicKey.DSA.construct(y,g,p,q,x)
	K=DSA.construct((y,g,p,q,x),consistency_check=True)
	#Tomamos el tiempo en que inicia la ejecución de la firma
	t0 = default_timer()
	#Hash del mensaje
	hash_obj = SHA1.new(message)
	#Firma del mensaje
	signer = DSS.new(K, 'fips-186-3')
	signature = signer.sign(hash_obj)
	#Tomamos el tiempo en que termina la ejecución de la firma
	t1 = default_timer()
	#Se imprime el tiempo total de ejecución de la firma el cual es t1-t0
	t_s_dsa.append("{0:0.10f}".format(t1-t0))

	###Para Verificar###
	##Carga de llave pública
	pub_key = DSA.import_key(K.publickey().export_key())
	#Tomamos el tiempo en que inicia la ejecución de la verifición
	t0 = default_timer()
	#Hash del mensaje
	hash_obj_ver = SHA1.new(message)
	#Verificamos Firma
	verifier = DSS.new(pub_key, 'fips-186-3')

	# Verify the authenticity of the message
	try:
	    verifier.verify(hash_obj, signature)
	    #print ("The message is authentic.")
	except ValueError:
	    #print ("The message is not authentic.")
	    pass
	#Tomamos el tiempo en que termina la ejecución de la firma
	t1 = default_timer()
	#Se imprime el tiempo total de ejecución de la firma el cual es t1-t0
	t_v_dsa.append("{0:0.10f}".format(t1-t0))

def ecdsa_bf(m):
	global t_s_ecdsa_bf
	global t_v_ecdsa_bf

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
	#Alternativa de conversion, para mensajes hexadecimales
	m = bytes.fromhex(m)

	#Instancia de la curva NIST K-571
	E = ec.SECT571K1()
	#Generacion de la llave publica
	pubs = ec.EllipticCurvePublicNumbers(x=Ux, y=Uy, curve=E)
	kPub = pubs.public_key()

	#Generacion de la llave privada
	k = ec.EllipticCurvePrivateNumbers(private_value=d, public_numbers=pubs)
	kPr = k.private_key()

	#Tomamos el tiempo en que inicia la ejecución de la firma
	t0 = default_timer()
	#Generacion de la firma
	s = kPr.sign(data=m, signature_algorithm=ec.ECDSA(hashes.SHA1()))
	#ds = utils.decode_dss_signature(s)
	#Tomamos el tiempo en que termina la ejecución de la firma
	t1 = default_timer()
	#Se imprime el tiempo total de ejecución de la firma el cual es t1-t0
	t_s_ecdsa_bf.append("{0:0.10f}".format(t1-t0))


	#Mensaje
	#Tomamos el tiempo en que inicia la ejecución de la verificación
	t0 = default_timer()
	#Verificacion de la firma
	try:
	    #Uso de la llave publica para verificar
	    kPub.verify(signature=s, data=m, signature_algorithm=ec.ECDSA(hashes.SHA1()))
	    #print("Firma valida")
	except(exceptions.InvalidSignature):
	    #print("Firma no valida")
	    pass
	#Tomamos el tiempo en que termina la ejecución de la verificación
	t1 = default_timer()
	#Se imprime el tiempo total de ejecución de la verificación el cual es t1-t0
	t_v_ecdsa_bf.append("{0:0.10f}".format(t1-t0))

def ecdsa_pf(msg):
	global t_s_ecdsa_pf
	global t_v_ecdsa_pf

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

	msg = bytes.fromhex(msg)

	#Se crea la curva eleiptica sobre el campo primo
	ECC = ec.SECP521R1()

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

	#Tomamos el tiempo en que inicia la ejecución de la firma
	t0 = default_timer()
	#Se hace la firma
	leFigme = privKey.sign(data=msg, signature_algorithm=ec.ECDSA(hashes.SHA1()))
	#ds = utils.decode_dss_signature(leFigme)
	#Tomamos el tiempo en que termina la ejecución de la firma
	t1 = default_timer()
	#Se imprime el tiempo total de ejecución de la verificación el cual es t1-t0
	t_s_ecdsa_pf.append("{0:0.10f}".format(t1-t0))

	#Tomamos el tiempo en que inicia la ejecución de la verificación
	t0 = default_timer()

	#Verificación de la firma
	try:
		pubKey.verify(signature=leFigme, data=msg, signature_algorithm=ec.ECDSA(hashes.SHA1()))
		#print("La firma es valida")
	except(exceptions.InvalidSignature):
		#print("Firma valida")
		pass
	#Tomamos el tiempo en que termina la ejecución de la verificación
	t1 = default_timer()
	#Se imprime el tiempo total de ejecución de la verificación el cual es t1-t0
	t_v_ecdsa_pf.append("{0:0.10f}".format(t1-t0))


#Función impresión tabla
def impresion(vector,t_rsa,t_dsa,t_ecb_b,t_ecb_p):
	valores = {"Vectores (Bytes)": vector,"RSA_PSS": t_rsa,"DSA": t_dsa, "ECDSA_BF": t_ecb_b, "ECDSA_PF": t_ecb_p}
	tabla = pd.DataFrame(valores)
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
	cont = [0, 0, 0, 0, 0]
	suma = [0, 0, 0, 0, 0]
	for i in range(len(tam)):
		if tam[i] == 128:
			agregar(tiempo[i], 4, cont, suma)
		elif tam[i] == 64:
			agregar(tiempo[i], 3, cont, suma)
		elif tam[i] == 32:
			agregar(tiempo[i], 2, cont, suma)
		elif tam[i] == 16:
			agregar(tiempo[i], 1, cont, suma)
		elif tam[i] == 8:
			agregar(tiempo[i], 0, cont, suma)
	for i in range(len(suma)):
		suma[i] = suma[i] / cont[i]
	return suma

def agregar(v, i, cont, suma):
	cont[i] += 1
	suma[i] += float(v)

#Contador de vectores
cont=0

#lista firmas
f_rsa_pps=[]
f_aes_cbc=[]
f_aes_ecb=[]

#Lista de todos los tiempos
t_s_rsa_pps=[]	#Signing
t_v_rsa_pps=[]	#Verify
t_s_dsa=[]		#Signing
t_v_dsa=[]		#Verify
t_s_ecdsa_pf=[]	#Signing
t_v_ecdsa_pf=[]	#Verify
t_s_ecdsa_bf=[]	#Signing
t_v_ecdsa_bf=[]	#Verify


vectores=[]

#Leer valor del vector de un archivo
archivo = open('vectores_sign_verify.txt','r')
for vector in archivo:
	##Si no es un comentario
	if(vector.strip('\n')[0]!='#'):
		cont+=1
		vectores.append(len(vector.strip("Msg = ").strip('\n'))//2)
		rsa_pps(vector.strip("Msg = ").strip('\n'))
		dsa(vector.strip("Msg = ").strip('\n'))
		ecdsa_bf(vector.strip("Msg = ").strip('\n'))
		ecdsa_pf(vector.strip("Msg = ").strip('\n'))

archivo.close()


#Guardar salida original
oldstdout = sys.stdout
#Crear y abrir archivo
f = open('Signing.txt', 'w')
#Redirigir la salida estandar
sys.stdout = f

print("\n\t\t\t##########Tabla Firma ##########")
#Impresión tabla cifrado
impresion(vectores,t_s_rsa_pps,t_s_dsa,t_s_ecdsa_bf,t_s_ecdsa_pf)
print("\nPromedio RSA-PSS: ",promedio(t_s_rsa_pps))
print("\nPromedio DSA: ",promedio(t_s_dsa))
print("\nPromedio ECDSA Binary Field: ",promedio(t_s_ecdsa_bf))
print("\nPromedio ECDSA Prime Field: ",promedio(t_s_ecdsa_pf))

#vaciar el buffer de salida
sys.stdout.flush()
#Cerrar archivo y cambiar el archivo
f.close()
f = open('Verifying.txt', 'w')
#Redirigir la salida estandar
sys.stdout = f

print("\n\t\t\t##########Tabla Verificación ##########")
#Impresión tabla descifrado
impresion(vectores,t_v_rsa_pps,t_v_dsa,t_v_ecdsa_bf,t_v_ecdsa_pf)
print("\nPromedio RSA-PSS: ",promedio(t_v_rsa_pps))
print("\nPromedio DSA: ",promedio(t_v_dsa))
print("\nPromedio ECDSA Binary Field: ",promedio(t_v_ecdsa_bf))
print("\nPromedio ECDSA Prime Field: ",promedio(t_v_ecdsa_pf))

#vaciar el buffer de salida
sys.stdout.flush()
#Cerrar archivo y volver salida original
f.close()
sys.stdout = oldstdout

#Graficado de firmas
pl.figure(1)
pl.plot([8, 16, 32, 64, 128], promedioTamano(vectores, t_s_rsa_pps), label='RSA-PPS')
pl.plot([8, 16, 32, 64, 128], promedioTamano(vectores, t_s_dsa), label='DSA')
pl.plot([8, 16, 32, 64, 128], promedioTamano(vectores, t_s_ecdsa_pf), label='ECDSA Primos')
pl.plot([8, 16, 32, 64, 128], promedioTamano(vectores, t_s_ecdsa_bf), label='ECDSA Binarios')
pl.xlabel("Tamaño del mensaje firmado")
pl.ylabel("Tiempo de procesamiento")
pl.title("Algoritmos de Firma digital")
pl.legend()
#Guardar grafico con los resultados
pl.savefig("Signing.png")

#Graficado de verificaciones
pl.figure(2)
pl.plot([8, 16, 32, 64, 128], promedioTamano(vectores, t_v_rsa_pps), label='RSA-PPS')
pl.plot([8, 16, 32, 64, 128], promedioTamano(vectores, t_v_dsa), label='DSA')
pl.plot([8, 16, 32, 64, 128], promedioTamano(vectores, t_v_ecdsa_pf), label='ECDSA Primos')
pl.plot([8, 16, 32, 64, 128], promedioTamano(vectores, t_v_ecdsa_bf), label='ECDSA Binarios')
pl.xlabel("Tamaño del mensaje obtenido")
pl.ylabel("Tiempo de procesamiento")
pl.title("Verificacion de Firma digital")
pl.legend()
#Guardar grafico con los resultados
pl.savefig("Veryfying.png")

print("Se han generado los resultados de los algoritmos de Firma y Verificación")
