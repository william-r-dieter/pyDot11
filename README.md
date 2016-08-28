# pyDot11

### pip install pyDot11-0.1.tar.gz

from pyDot11 import *

encPkts = rdpcap('PCAPs/ICMPs/wep_pings.pcap')

encPkts[0].summary()

decPkt, iVal = wepDecrypt(encPkts[0], keyText='0123456789')

decPkt.summary()



