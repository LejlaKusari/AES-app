from django.contrib import admin
from .models import Encryption, Decryption

admin.site.register([Encryption, Decryption])
