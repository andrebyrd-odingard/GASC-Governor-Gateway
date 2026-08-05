import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

jwt_private_key = ec.generate_private_key(ec.SECP256R1())
JWT_PUBLIC_KEY = jwt_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')
JWT_PRIVATE_KEY_PEM = jwt_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

os.environ["JWT_PUBLIC_KEY"] = JWT_PUBLIC_KEY
os.environ["DEBUG_MODE"] = "true"
