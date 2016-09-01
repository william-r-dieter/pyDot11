from binascii import hexlify, unhexlify
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
        """Take a packet with [Dot11WEP] and apply RC4 to get the [LLC]
        """
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
        ## Calculate the WEP Integrity Check Value (ICV)
        wepICV = self.endSwap(hex(crc32(str(pkt[LLC])) & 0xffffffff))
        
        ## Concatenate ICV to the [LLC]
        stream = str(pkt[LLC]) + unhexlify(wepICV)
        
        ## crypt
        seed = self.seedGen(iVal, unhexlify(keyText))
        return rc4(stream, seed)


    def enBuilder(self, pkt, stream, iVal):
        ## Mirror the packet
        reflection = pkt.copy()

        ## Remove the LLC layer
        del reflection[LLC]

        ## Add the Dot11WEP layer
        reflection = reflection/Dot11WEP(iv = iVal, keyid = 0, wepdata = stream)
        return reflection


    def endSwap(self, value):
        """Expect hex format of '0x..."""
        x = value.replace('0x', '')
        start = 0
        end = 2
        swapList = []
        for i in range(len(x)/2):
            swapList.append(x[start:end])
            start += 2
            end += 2
        swapList.reverse()
        s = ''
        for i in swapList:
            s += i
        return s
        

class Wpa(object):

    def __init__(self):
        self.shakeDict = {}
