import os
import json
import base64
import datetime
import hashlib
import logging
from typing import Dict, Tuple, Optional
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization

class AuthenticationManager:
    def __init__(self, username: str, keys_path: str):
        self.username = username
        self.keys_path = keys_path
        self.private_key = None
        self.public_key = None
        self.verified_peers: Dict[str, Dict] = {}
        self.logger = logging.getLogger(f"AuthManager-{username}")
        self._load_or_create_keys()

    def _load_or_create_keys(self, master_password: Optional[str] = None):
        key_file = os.path.join(self.keys_path, f"{self.username}_keys.json")
        os.makedirs(self.keys_path, exist_ok=True)

        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                file_data = json.load(f)
            if file_data.get('encrypted', False):
                if not master_password:
                    raise ValueError("Master password required for encrypted keys")
                decrypted_data = self._decrypt_data(base64.b64decode(file_data['data']), master_password)
                key_data = json.loads(decrypted_data.decode('utf-8'))
            else:
                key_data = file_data['data']
            self.private_key = serialization.load_pem_private_key(
                base64.b64decode(key_data['private_key']),
                password=None,
                backend=default_backend()
            )
            self.public_key = serialization.load_pem_public_key(
                base64.b64decode(key_data['public_key']),
                backend=default_backend()
            )
            self.verified_peers = key_data.get('verified_peers', {})
        else:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()
            self._save_keys()

    def _encrypt_data(self, data: bytes, password: str) -> bytes:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(password.encode())
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return salt + iv + ciphertext

    def _decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def _save_keys(self, master_password: Optional[str] = None):
        key_file = os.path.join(self.keys_path, f"{self.username}_keys.json")
        key_data = {
            'private_key': base64.b64encode(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )).decode('utf-8'),
            'public_key': base64.b64encode(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode('utf-8'),
            'verified_peers': self.verified_peers
        }
        if master_password:
            encrypted_data = self._encrypt_data(json.dumps(key_data).encode('utf-8'), master_password)
            file_data = {'encrypted': True, 'data': base64.b64encode(encrypted_data).decode('utf-8')}
        else:
            file_data = {'encrypted': False, 'data': key_data}
        with open(key_file, 'w') as f:
            json.dump(file_data, f, indent=2)

    def generate_fingerprint(self) -> str:
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_key_bytes).hexdigest()[:16]

    def verify_peer(self, peer_id: str, peer_fingerprint: str) -> bool:
        for existing_id, info in self.verified_peers.items():
            if info['fingerprint'] == peer_fingerprint and existing_id != peer_id:
                self.verified_peers[existing_id]['verified_at'] = str(datetime.datetime.now())
                self._save_keys()
                return True
        self.verified_peers[peer_id] = {
            'fingerprint': peer_fingerprint,
            'verified_at': str(datetime.datetime.now())
        }
        self._save_keys()
        return True

    def is_peer_verified(self, peer_id: str) -> bool:
        return peer_id in self.verified_peers

    def rotate_keys(self, master_password: str) -> Tuple[bool, str]:
        try:
            old_private_key = self.private_key
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()
            new_fingerprint = self.generate_fingerprint()
            self._save_keys(master_password)
            self.logger.info(f"Keys rotated successfully, new fingerprint: {new_fingerprint}")
            return True, new_fingerprint
        except Exception as e:
            self.private_key = old_private_key
            self.logger.error(f"Key rotation failed: {e}")
            return False, ""