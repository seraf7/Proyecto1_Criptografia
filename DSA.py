from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1

#Inicializamos valores de llaves
p=int("a8f9cd201e5e35d892f85f80e4db2599a5676a3b1d4f190330ed3256b26d0e80a0e49a8fffaaad2a24f472d2573241d4d6d6c7480c80b4c67bb4479c15ada7ea8424d2502fa01472e760241713dab025ae1b02e1703a1435f62ddf4ee4c1b664066eb22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5b06439ac9c7e9d8bde283",16)
q=int("f85f0f83ac4df7ea0cdf8f469bfeeaea14156495",16)
g=int("2b3152ff6c62f14622b8f48e59f8af46883b38e79b8c74deeae9df131f8b856e3ad6c8455dab87cc0da8ac973417ce4f7878557d6cdf40b35b4a0ca3eb310c6a95d68ce284ad4e25ea28591611ee08b8444bd64b25f3f7c572410ddfb39cc728b9c936f85f419129869929cdb909a6a3a99bbe089216368171bd0ba81de4fe33",16)
x=int("c53eae6d45323164c7d07af5715703744a63fc3a",16)
y=int("313fd9ebca91574e1c2eebe1517c57e0c21b0209872140c5328761bbb2450b33f1b18b409ce9ab7c4cd8fda3391e8e34868357c199e16a6b2eba06d6749def791d79e95d3a4d09b24c392ad89dbf100995ae19c01062056bb14bce005e8731efde175f95b975089bdcdaea562b32786d96f5a31aedf75364008ad4fffebb970b",16)

#Creación de un objeto de llave DSA
#Crypto.PublicKey.DSA.construct(y,g,p,q,x)
K=DSA.construct((y,g,p,q,x),consistency_check=True)

#Mensaje
message = b"d2bcb53b044b3e2e4b61ba2f91c0995fb83a6a97525e66441a3b489d9594238bc740bdeea0f718a769c977e2de003877b5d7dc25b182ae533db33e78f2c3ff0645f2137abc137d4e7d93ccf24f60b18a820bc07c7b4b5fe08b4f9e7d21b256c18f3b9d49acc4f93e2ce6f3754c7807757d2e1176042612cb32fc3f4f70700e25"
#Hash del mensaje
hash_obj = SHA1.new(message)
#Firma del mensaje
signer = DSS.new(K, 'fips-186-3')
signature = signer.sign(hash_obj)

###Para Verificar###
#Hash del mensaje
hash_obj_ver = SHA1.new(message)
##Carga de llave pública
pub_key = DSA.import_key(K.publickey().export_key())
#Verificamos Firma
verifier = DSS.new(pub_key, 'fips-186-3')

print(verifier)

#pub_key=DSA.import_key(y)
# Verify the authenticity of the message
try:
    verifier.verify(hash_obj, signature)
    print ("The message is authentic.")
except ValueError:
    print ("The message is not authentic.")

