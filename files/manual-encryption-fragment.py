#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a fragmented wep message given the WEP key"""

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
# Génération d'un IV de 24 bits
iv = get_random_bytes(3)

message_part0 = b'hello world!'
message_part1 = b'message made'
message_part2 = b'with scapy !'
messages = [message_part0, message_part1, message_part2]

# rc4 seed est composé de IV+clé
seed = iv + key

# Calcul de l'ICV du message
count = 0
for i, message in enumerate(messages):

    # Creation de l'ICV a l'aide d'un CRC32
    icv = crc32(message).to_bytes(4, byteorder='little')

    # Les données a chiffrer sont le message et l'ICV
    message_to_encrypt = message + icv

    # chiffrement rc4
    cipher = RC4(seed, streaming=False)
    encrypted_data = cipher.crypt(message_to_encrypt)

    # On extrait l'ICV chiffré (4 dernier byte)
    encrypted_icv = int.from_bytes(encrypted_data[-4:], byteorder='big')

    # On regarde si c'est notre dernier paquet, si c'est le cas on ne met pas le flag MF (more fragment)
    flags = ""
    if i != len(messages)-1:
        flags = "to-DS+protected+MF"
    else:
        flags = "to-DS+protected"

    # On creer notre paquet WEP
    packet = RadioTap() / Dot11(type='Data', FCfield=flags) / Dot11WEP(iv=iv, wepdata=encrypted_data[:-4], icv=encrypted_icv)
    # On donne le numéro de paquet
    packet.SC = i
    wrpcap('task3.cap', packet, append=True)
