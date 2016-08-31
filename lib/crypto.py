import re
from binascii import crc32, hexlify, unhexlify
from rc4 import rc4
from scapy.all import *

class Wep(object):
    """All things WEP related"""

    def __init__(self):
        pass
    
    
    def seedGen(self, iv, keyText):
        """Currently works with 40-bit and 104-bit"""
        keyLen = len(keyText)
        
        ## 40-bit
        if keyLen == 5:
            key = unhexlify(re.sub(' ', '', hexstr(keyText, onlyhex=1)))
        elif keyLen == 10:
            key = unhexlify(keyText)
        
        ## 104-bit
        if keyLen == 13:
            key = unhexlify(re.sub(' ', '', hexstr(keyText, onlyhex=1)))
        elif keyLen == 26:
            key = unhexlify(keyText)
            
        return iv + key
    
    
    def deBuilder(self, pkt, stream):
        """Take the pkt object and apply stream to [LLC]"""
        ## Mirror the packet
        reflection = pkt.copy()

        ## Remove the encryption layer
        del reflection[Dot11WEP]

        ## Add the LLC layer using the decrypted stream
        reflection = reflection/LLC(stream)
        return reflection


    def decoder(self, pkt, keyText):
        """Take a packet with [Dot11WEP] and apply RC4 to get the [LLC]
        This function should not need to return fullStream,
        however, because of quirks I've noticed, I return
        fullStream and stream.
        The seed doesn't need to be returned, but why calculate again...
        """
        ## Re-use the IV for comparative purposes
        iVal = pkt[Dot11WEP].iv
        seed = self.seedGen(iVal, keyText)
        
        ## Grab full stream
        fullStream = rc4(pkt[Dot11WEP].wepdata, seed)
        
        ## Drop the 4 icv bytes
        stream = fullStream[0:-4]
        
        ## Return the fullstream, stream and iv
        return fullStream, stream, iVal, seed


    def encoder(self, pkt, iVal, keyText):
        ## Calculate the WEP Integrity Check Value (ICV)
        ## Deal with negative crc
        wepICV = crc32(str(pkt[LLC])) & 0xffffffff
        plainText = str(pkt[LLC])
        stream = plainText
        
        ## crypt
        seed = self.seedGen(iVal, unhexlify(keyText))
        return rc4(stream, seed), wepICV


    def enBuilder(self, pkt, stream, iVal, wepICV):
        ## Mirror the packet
        reflection = pkt.copy()

        ## Remove the LLC layer
        del reflection[LLC]

        ## Add the Dot11WEP layer
        reflection = reflection/Dot11WEP()
        reflection[Dot11WEP].iv = iVal
        reflection[Dot11WEP].keyid = 0
        reflection[Dot11WEP].wepdata = stream
        reflection[Dot11WEP].icv = wepICV

        return reflection
        

class Wpa(object):

    def __init__(self):
        self.shakeDict = {}
