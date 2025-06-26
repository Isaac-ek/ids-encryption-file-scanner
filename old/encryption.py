import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from typing import Optional, Tuple
from getpass import getpass

class AESGCMCipher:
    """
    AES-GCM encryption/decryption with secure key and IV management.
    Suitable for file and data encryption in production workflows.
    """
    def __init__(self, key: Optional[bytes] = None, iv: Optional[bytes] = None):
        self.key = key or os.urandom(32)  # 256-bit key
        self.iv = iv or os.urandom(12)    # 96-bit IV (recommended for GCM)

    @staticmethod
    def generate_key_iv() -> Tuple[bytes, bytes]:
        return os.urandom(32), os.urandom(12)

    def encrypt(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        return aesgcm.encrypt(self.iv, data, None)

    def decrypt(self, ciphertext: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(self.iv, ciphertext, None)

    def encrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as f:
            data = f.read()
        ct = self.encrypt(data)
        with open(outfile, 'wb') as f:
            f.write(ct)

    def decrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as f:
            ct = f.read()
        pt = self.decrypt(ct)
        with open(outfile, 'wb') as f:
            f.write(pt)

    def export_key_iv(self) -> Tuple[bytes, bytes]:
        return self.key, self.iv

    @classmethod
    def from_key_iv(cls, key: bytes, iv: bytes):
        return cls(key, iv)

class RSACipher:
    """
    RSA encryption/decryption with key management and serialization.
    Suitable for hybrid encryption and secure key exchange in production.
    """
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key or (private_key.public_key() if private_key else None)

    @staticmethod
    def generate_keypair(key_size=2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    @classmethod
    def from_private_key(cls, pem_data: bytes, password: Optional[bytes] = None):
        private_key = serialization.load_pem_private_key(pem_data, password=password, backend=default_backend())
        return cls(private_key=private_key)

    @classmethod
    def from_public_key(cls, pem_data: bytes):
        public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        return cls(public_key=public_key)

    def encrypt(self, data: bytes) -> bytes:
        if not self.public_key:
            raise ValueError("Public key is required for encryption.")
        return self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.private_key:
            raise ValueError("Private key is required for decryption.")
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def export_private_key(self, password: Optional[bytes] = None) -> bytes:
        encryption_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )

    def export_public_key(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as f:
            data = f.read()
        ct = self.encrypt(data)
        with open(outfile, 'wb') as f:
            f.write(ct)

    def decrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as f:
            ct = f.read()
        pt = self.decrypt(ct)
        with open(outfile, 'wb') as f:
            f.write(pt)

def initialize_or_load_rsa_keys(key_path: str, pub_path: str) -> RSACipher:
    """
    CLI-based utility to initialize or load an RSA keypair with password protection.
    On first launch, prompts admin to set a password, generates and saves encrypted private key and public key.
    On subsequent launches, prompts for password to decrypt and load the private key.
    Returns an RSACipher instance.
    """
    if not os.path.exists(key_path):
        print("No private key found. Initializing new RSA keypair.")
        while True:
            password = getpass("Set a password to protect your private key: ").encode()
            password_confirm = getpass("Confirm password: ").encode()
            if password != password_confirm:
                print("Passwords do not match. Try again.")
            elif len(password) < 6:
                print("Password too short. Use at least 6 characters.")
            else:
                break
        private_key, public_key = RSACipher.generate_keypair()
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(key_path, 'wb') as f:
            f.write(priv_pem)
        with open(pub_path, 'wb') as f:
            f.write(pub_pem)
        print(f"Private key saved to {key_path} (encrypted). Public key saved to {pub_path}.")
        return RSACipher(private_key=private_key)
    else:
        print("Private key found. Please enter your password to unlock it.")
        for attempt in range(3):
            password = getpass("Enter your private key password: ").encode()
            try:
                with open(key_path, 'rb') as f:
                    priv_pem = f.read()
                private_key = serialization.load_pem_private_key(priv_pem, password=password, backend=default_backend())
                print("Private key successfully loaded.")
                return RSACipher(private_key=private_key)
            except Exception as e:
                print("Incorrect password or corrupted key. Try again.")
        raise RuntimeError("Failed to load private key after 3 attempts.") 