import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
from django.db import models    


class Encryption(models.Model):
    message = models.CharField(max_length=1024)
    key = models.CharField(max_length=32)
    iv = models.CharField(default=b64encode(os.urandom(16)).decode(), max_length=128)

    choices = (
        ('cbc', 'CBC'),
        ('ctr', 'CTR'),
        ('ofb', 'OFB'),
        ('cfb', 'CFB'),
        ('cfb8', 'CFB8'),
    )
    mode = models.CharField(max_length=4, choices=choices)

    encrypted_message = models.CharField(max_length=2048, null=True, blank=True)

    def encrypt(self):
        key_padder = padding.PKCS7(128).padder()
        padded_key = key_padder.update(self.key.encode()) + key_padder.finalize()
        
        cipher = Cipher(algorithms.AES(padded_key), eval('modes.{}({})'.format(self.mode.upper(), b64decode(self.iv))), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()

        padded_message = padder.update(self.message.encode()) + padder.finalize()

        ct = encryptor.update(padded_message) + encryptor.finalize()

        return b64encode(ct).decode('utf-8')

    def save(self, *args, **kwargs):
        self.encrypted_message = self.encrypt()
        super(Encryption, self).save(*args, **kwargs)

    def __str__(self):
        return self.encrypted_message


class Decryption(models.Model):
    encrypted_message = models.CharField(max_length=2048)
    key = models.CharField(max_length=32)
    iv = models.CharField(max_length=128)

    choices = (
        ('cbc', 'CBC'),
        ('ctr', 'CTR'),
        ('ofb', 'OFB'),
        ('cfb', 'CFB'),
        ('cfb8', 'CFB8'),
    )
    mode = models.CharField(max_length=4, choices=choices)

    decrypted_message = models.CharField(max_length=1024, null=True, blank=True)

    def decrypt(self):
        key_padder = padding.PKCS7(128).padder()
        padded_key = key_padder.update(self.key.encode()) + key_padder.finalize()

        cipher = Cipher(algorithms.AES(padded_key), eval('modes.{}({})'.format(self.mode.upper(), b64decode(self.iv))), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted = decryptor.update(b64decode(self.encrypted_message)) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_message = unpadder.update(decrypted) + unpadder.finalize()

        return unpadded_message.decode()

    def save(self, *args, **kwargs):
        self.decrypted_message = self.decrypt()
        super(Decryption, self).save(*args, **kwargs)

    def __str__(self):
        return self.decrypted_message