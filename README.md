# pyDot11

### pip install pyDot11-0.1.tar.gz

from pyDot11 import *

encPkts = rdpcap('PCAPs/ICMPs/wep_pings.pcap')

encPkts[3].summary()

decPkt, iVal = wepDecrypt(encPkts[3], keyText='0123456789')

decPkt.summary()

encPkt = wepEncrypt(decPkt, '0123456789', iVal)

encPkt.summary()

encPkt
encPkts[3]

encPkt == encPkts[3]


