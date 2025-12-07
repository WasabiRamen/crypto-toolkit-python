from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

"""AES encryption and decryption using the cryptography library."""



class AESCryptor:
    def __init__(self, key: bytes):
        """
        Initialize AES with a key.
        
        Args:
            key: AES key (16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-CBC mode.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Tuple of (iv, ciphertext)
        """
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, ciphertext

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using AES-CBC mode.
        
        Args:
            iv: Initialization vector
            ciphertext: Data to decrypt
            
        Returns:
            Decrypted plaintext
        """
        # Decrypt
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext