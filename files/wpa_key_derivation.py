#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__authors__     = "Crescence Yimnaing && Francine Youndzo"
__copyright__   = "Copyright 2019, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array 
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = "SWI"
APmac       = a2b_hex("cebcc8fdcab7")
Clientmac   = a2b_hex("0013efd015bd")

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
SNonce      = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") 

#cf "Quelques détails importants" dans la donnée
print ('\n\nValues used to derivate keys')
print ('============================')
print ('Passphrase: ' + passPhrase + '\n' )
print ('SSID: ' + ssid + '\n' )
print ('AP Mac: ' + b2a_hex(APmac) + '\n' )
print ('CLient Mac: ' + b2a_hex(Clientmac) + '\n' )
print ('AP Nonce: ' + b2a_hex(ANonce) + '\n' )
print ('Client Nonce: ' + b2a_hex(SNonce) + '\n' )

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(a2b_hex(pmk),A,B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)

#claculate mac address of ssid, AP and customer
ssid   = wpa[0].info
AP_mac = wpa[1].addr2
Client_mac = wpa[0].addr1

#calculate nonces
A_nonce = a2b_hex((wpa[5].load).encode("hex")[26:90])
S_nonce = a2b_hex((wpa[6].load).encode("hex")[26:90])

#claculate mic4way
mic4way = (wpa[8].load).encode("hex")[154:186]

#Recovring data
data1  = b2a_hex(str((wpa[8])[EAPOL]))
data   = list(data1)

for i in range(162,194):
    data[i] = '0'
data = ("-".join(data)).replace("-", "")

print ('\nResults recovring from capture ')
print ('============================')
print ('Data: ' + data + '\n' )
print ('SSID: ' + ssid + '\n' )
print ('AP Mac: ' + b2a_hex(AP_mac) + '\n' )
print ('CLient Mac: ' + b2a_hex(Client_mac ) + '\n' )
print ('AP Nonce: ' + b2a_hex(A_nonce) + '\n' )
print ('Client Nonce: ' + b2a_hex(S_nonce) + '\n' )
print ('mic: ' + mic4way + '\n')

print ('\nResults of the key expansion ')
print ('=============================')
print ('PMK: ' + pmk + '\n' )
print ('PTK: ' + b2a_hex(ptk) +'\n')
print ('KCK: ' + b2a_hex(ptk[0:16]) + '\n')
print ('KEK: ' + b2a_hex(ptk[16:32]) + '\n')
print ('TK: ' + b2a_hex(ptk[32:48]) + '\n')
print ('MICK: ' + b2a_hex(ptk[48:64]) + '\n')
print ('MIC: ' + mic.hexdigest() + '\n')