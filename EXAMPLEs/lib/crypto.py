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
            key = unhexlify(hexstr(keyText, onlyhex=1).replace(' ', ''))
        elif keyLen == 10:
            key = unhexlify(keyText)
        
        ## 104-bit
        if keyLen == 13:
            key = unhexlify(hexstr(keyText, onlyhex=1).replace(' ', ''))
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
        """Take a packet with [Dot11WEP] and apply RC4 to get the [LLC]"""
        ## Re-use the IV for comparative purposes
        iVal = pkt[Dot11WEP].iv
        seed = self.seedGen(iVal, keyText)
        
        ## Grab full stream
        fullStream = rc4(pkt[Dot11WEP].wepdata, seed)
        
        ## Drop the 4 icv bytes
        stream = fullStream[0:-4]
        
        ## Return the stream, iv and seed
        return stream, iVal, seed


    def encoder(self, pkt, iVal, keyText):
        """Create [LLC] encoded as .wepdata"""
        ## Calculate the WEP Integrity Check Value (ICV)
        wepICV = crc32(str(pkt[LLC]))
        stream = str(pkt[LLC]) + unhexlify(hex(wepICV).replace('0x', ''))
        
        ## crypt
        seed = self.seedGen(iVal, unhexlify(keyText))
        return rc4(stream, seed), wepICV


    def enBuilder(self, pkt, stream, iVal, wepICV):
        """Assemble WEP encrypted packet"""
        ## Mirror the packet
        reflection = pkt.copy()

        ## Remove the LLC layer
        del reflection[LLC]

        ## Add the Dot11WEP layer
        reflection = reflection/Dot11WEP(iv = iVal, keyid = 0, wepdata = stream, icv = wepICV)

        return reflection
