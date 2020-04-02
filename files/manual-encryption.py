#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__ = "Remi Poulard, Caroline Monthoux"
__copyright__ = "Copyright 2019, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "remi.poulard@heig-vd.ch, caroline.monthoux@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11WEP
from rc4 import RC4
from Crypto.Random import get_random_bytes
from zlib import crc32

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
iv = get_random_bytes(3)

# Meme message que ex1 pour tester
message = bytes.fromhex("aaaa03000000080600010800060400019027e4ea61f2c0a80166000000000000c0a801c8")

# rc4 seed est composé de IV+clé
seed = iv + key

# Calcul de l'ICV du message
icv = crc32(message).to_bytes(4, byteorder='little')

# Les données a chiffrer c'est le message et l'ICV
message_to_encrypt = message + icv

# chiffrement rc4
cipher = RC4(seed, streaming=False)
encrypted_data = cipher.crypt(message_to_encrypt)

# On extrait l'ICV chiffré (4 dernier byte)
encrypted_icv = int.from_bytes(encrypted_data[-4:], byteorder='big')
# On creer notre paquet WEP
packet = RadioTap() / Dot11(type='Data', FCfield='to-DS+protected') / Dot11WEP(iv=iv, wepdata=encrypted_data[:-4], icv=encrypted_icv)

wrpcap('task2.cap', packet, append=True)
