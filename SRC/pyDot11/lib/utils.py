import struct

from scapy.utils import hexstr, PcapReader, PcapWriter, rdpcap, wrpcap
from scapy.plist import PacketList
from zlib import crc32
import binascii, pyDot11

class Pcap(object):
    """Class to deal with pcap specific tasks"""
    
    def crypt2plain(self, pcapFile, encType, key):
        """Converts an encrypted stream to unencrypted stream
        Returns the unencrypted stream input as a scapy PacketList object
        
        Future plans involve offering a yield parameter so that pcapList,
        instead returns as a generated object; should save memory this way.
        
        Does not have the capability to diff between multiple keys encTypes
        Possible workaround for this is taking the try and using except,
        creating a return to let the user know which objs to retry on
        For now, skipping.
        """
        
        ## Use the generator of PcapReader for memory purposes
        pObj = PcapReader(pcapFile)
        pcapList = []
        
        ## Deal with WEP
        if encType == 'WEP':
            for i in pObj:
                try:
                    pkt, iv = pyDot11.wepDecrypt(i, key)
                except:
                    pkt = i
                pcapList.append(pkt)
        
        ## Return the stream like a normal Scapy PacketList
        return PacketList(res = pcapList)
    
        
        
class Packet(object):
    """Class to deal with packet specific tasks"""
    
    def __init__(self):
        self.nonceDict = {'8a': 'a1',
                          '0a': 'a2',
                          'ca': 'a3',
                          '89': 't1',
                          '09': 't2',
                          'c9': 't3'}


    def byteRip(self, stream, chop = False, compress = False, order = 'first', output = 'hex', qty = 1):
        """Take a scapy hexstr(str(pkt), onlyhex = 1) and grab based on what you want

        chop is the concept of removing the qty based upon the order
        compress is the concept of removing unwanted spaces    
        order is concept of give me first <qty> bytes or gives me last <qty> bytes
        output deals with how the user wishes the stream to be returned
        qty is how many nibbles to deal with
        
        QTY IS DOUBLE THE NUMBER OF BYTES
        THINK OF QTY AS A NIBBLE
        2 NIBBLES FOR EVERY BYTE
        
        Important to note that moving to a pure string versus a list,
        will probably help with memory consumption
        
        Eventually, need to add a kwarg that allows us to specify,
        which bytes we want, i.e. first and last based on order
        """
        
        def pktFlow(pkt, output):
            if output == 'hex':
                return pkt
            if output == 'str':
                return binascii.unhexlify(str(pkt).replace(' ', ''))
            
        stream = hexstr(str(stream), onlyhex = 1)
        streamList = stream.split(' ')
        streamLen = len(streamList)

        ## Deal with first bytes
        if order == 'first':
            
            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[0:qty]), output)
            
            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[qty:]), output)
                
            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[0:qty]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[qty:]).replace(' ', ''), output)
        
        ## Deal with last bytes
        if order == 'last':
            
            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[streamLen - qty:]), output)
            
            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[:-qty]), output)
            
            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[streamLen - qty:]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[:-qty]).replace(' ', ''), output)


    def fcsGen(self, frame, start = None, end = None, mLength = 0, output = 'bytes'):
        """Return the FCS for a given frame"""
        frame = str(frame)
        frame = frame[start:end]
        fcs = crc32(frame) & 0xffffffff
        if output != 'int':
            # Make `fcs` into a unhexlified string
            fcs = struct.pack('<I', fcs)
            if output == 'bytes':
                return binascii.hexlify(fcs)
        return fcs
