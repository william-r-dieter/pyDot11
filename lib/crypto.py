import re
from binascii import crc32, hexlify, unhexlify
from rc4 import rc4
from scapy.all import *

class Wep(object):

    def __init__(self):
        pass
    
    
    def seedGen(self, iv, keyText):
        """Simple for now
        Experiments on 5-char ASCII have not been done yet
        Once those experiments are complete,
        this () will contain if logic to determine how to build the seed
        I theorize that 01234567890 will be parsed differently than ABCDE
        """
        return iv + keyText
    
    
    def deBuilder(self, pkt, stream):
        """Take 
        """
        
        ## Mirror the packet
        reflection = pkt.copy()

        ## Remove the encryption layer
        del reflection[Dot11WEP]

        ## Add the LLC layer
        reflection = reflection/LLC()

        ## Create the packet without encryption and return it
        llcStruct = LLC(stream)
        reflection[LLC] = llcStruct
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
        seed = self.seedGen(iVal, unhexlify(keyText))
        
        ## Grab full stream
        fullStream = rc4(pkt[Dot11WEP].wepdata, seed)
        
        ## Prep for removing the 4 icv bytes
        tmp = []
        stream = ''
        for i in range(len(fullStream) - 4):
            tmp.append(fullStream[i])
        for i in tmp:
            stream += i
        
        ## Return the fullstream, stream and iv
        return fullStream, stream, iVal, seed


    def encoder(self, pkt, iVal, keyText):
        ## Calculate the WEP Integrity Check Value (ICV)
        wepICV = crc32(str(pkt[LLC]))
        plainText = str(pkt[LLC])
        
        print 'wepICV is: ', wepICV
        print 'hex of ^ is: ', hex(wepICV)
        print 'unhexlify of ^ is: ', unhexlify(re.sub('0x', '', hex(wepICV)))
        print 'repr of ^ is: ', repr(unhexlify(re.sub('0x', '', hex(wepICV))))
        #stream = plainText + str(wepICV)
        #stream = plainText + hex(wepICV)
        #stream = plainText + unhexlify(re.sub('0x', '', hex(wepICV)))
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
    pass

