# Copyright (C) 2016 stryngs

### Transfer to Wpa Class
import hmac, hashlib, binascii, sha
from pbkdf2 import PBKDF2

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from rc4 import rc4
from scapy.all import *
from .lib.crypto import Wep, Wpa
from .lib.nic import Tap


## WEP PORTION
def wepDecrypt(pkt, keyText):
    """Encompasses the steps needed to decrypt a WEP packet"""
    stream, iVal, seed = wepCrypto.decoder(pkt, keyText)
    
    ## Decode the [LLC]
    decodedPacket = wepCrypto.deBuilder(pkt, stream)

    ## Flip FCField bits accordingly
    if decodedPacket[Dot11].FCfield == 65L:
        decodedPacket[Dot11].FCfield = 1L
    elif decodedPacket[Dot11].FCfield == 66L:
        decodedPacket[Dot11].FCfield = 2L
    
    return decodedPacket, iVal


def wepEncrypt(pkt, keyText, iVal = '\xba0\x0e', ):
    """Encompasses the steps needed to encrypt a WEP packet"""
    pkt = pkt.copy()
       
    ## Encode the LLC layer via rc4
    stream = wepCrypto.encoder(pkt, iVal, keyText)
    
    ## Build the packet minus the FCS
    encodedPacket = wepCrypto.enBuilder(pkt, stream, iVal)
    
    ## Flip FCField bits accordingly
    if encodedPacket[Dot11].FCfield == 1L:
        encodedPacket[Dot11].FCfield = 65L
    elif encodedPacket[Dot11].FCfield == 2L:
        encodedPacket[Dot11].FCfield = 66L
    
    ## Add the ICV
    encodedPacket[Dot11WEP].icv = int(wepCrypto.endSwap(hex(crc32(str(\
        encodedPacket[Dot11])[0:-4]) & 0xffffffff)), 16)

    return encodedPacket



## WPA PORTION
### Most of this will be classed in crypto.py
def eapolGrab():
    """Grab the EAPOL
    Needs logic in case of multiple auth at one
    """
    pkts = sniff(iface = 'wlan0mon', lfilter = lambda p: p.haslayer(EAPOL) \
        and p.type == 2, count = 4)
    vMAC = pkts[0][Dot11].addr1
    bMAC = pkts[0][Dot11].addr2
    eapolCapture = wpaCrypto.shakeDict[vMAC] = {}
    eapolCapture[bMAC] = pkts
    return vMAC, bMAC


def handShake():
    """Store EAPOLs based upon BSSID based upon originating MAC"""
    ### Create a way for new EAPOLs so that the old EAPOL is deleted
    vMAC, bMAC = eapolGrab()
    vicMAC = wpaCrypto.shakeDict[vMAC]
    bDict = vicMAC[bMAC]


def pmkGen(passwd, essid):
    """Silly return for now
    To view PMK, .encode('hex')
    """
    return PBKDF2(passwd, essid, 4096).read(32)


def PRF512(key, A, B):  
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key, A + chr(0x00) + B + chr(i), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


### Instantiations
wepCrypto = Wep()
wpaCrypto = Wpa()
dev = Tap()
subprocess.check_call('ifconfig tap0 up', shell = True)