from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import ecdsa
import os
import json


# 1. Ашық және жеке кілттерді жасау
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    return private_key, public_key


# Жеке кілтті сақтау
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)


# Ашық кілтті сақтау
def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)


# 2. Сандық қолтаңба жасау
def sign_transaction(private_key, data):
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


# Қолтаңбаны тексеру
def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


# 3. Аккаунт адрестері (ашық кілттен алу)
def get_address_from_public_key(public_key):
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashes.Hash(hashes.SHA256()).finalize().hex()


# 4. Әмиян GUI (қолданушы интерфейсі үшін қажет)
# Осы бөлікті кейін GUI кітапханаларымен толықтыруға болады

# Мысал:
private_key, public_key = generate_key_pair()
save_private_key(private_key, 'private_key.pem')
save_public_key(public_key, 'public_key.pem')

transaction_data = "Send 10 coins to Alice"
signature = sign_transaction(private_key, transaction_data)
print("Signature:", signature.hex())

is_valid = verify_signature(public_key, signature, transaction_data)
print("Signature valid:", is_valid)
