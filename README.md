# pyDot11

### pip install pyDot11-0.1.tar.gz

from pyDot11 import *

# Example of grabbing an encrypted packet, decrypting it, and then replaying it
encPkts = rdpcap('PCAPs/ICMPs/wep_pings.pcap')
encPkts[1].summary()
decPkt, iVal = wepDecrypt(encPkts[1], keyText='0123456789')
decPkt.summary()
encPkt = wepEncrypt(decPkt, '0123456789', iVal)
encPkt.summary()
encPkt
encPkts[1]
encPkt == encPkts[1]

# Example of taking a packet from Open Wifi, and then encrypting it
openPkts = rdpcap('PCAPs/ICMPs/open_pings.pcap')
openPkts[1].summary()
input = openPkts[1].__class__(str(openPkts[1])[0:-4])
encPkt = wepEncrypt(input, '0123456789')
encPkt.summary()

# Example of decrypting a pcap file
decList = pcap.crypt2plain('PCAPs/ICMPs/wep_pings.pcap', '0123456789')

