# pyDot11

### pip install pyDot11-0.5.tar.gz

````python
# Example of grabbing an encrypted packet, decrypting it, and then replaying it
from pyDot11 import *
encPkts = rdpcap('PCAPs/ICMPs/wep_pings.pcap')
encPkts[1].summary()
decPkt, iVal = wepDecrypt(encPkts[1], keyText='0123456789')
decPkt.summary()
encPkt = wepEncrypt(decPkt, '0123456789', iVal)
encPkt.summary()
encPkt
encPkts[1]
encPkt == encPkts[1]
````

````python
# Example of taking a packet from Open Wifi, and then encrypting it
from pyDot11 import *
openPkts = rdpcap('PCAPs/ICMPs/open_pings.pcap')
openPkts[1].summary()
input = openPkts[1].__class__(str(openPkts[1])[0:-4])
encPkt = wepEncrypt(input, '0123456789')
encPkt.summary()
````

````python
# Example of decrypting a pcap file
from pyDot11 import *
decList = pcap.crypt2plain('PCAPs/ICMPs/wep_pings.pcap', '0123456789')
````
