# pyDot11

## pyDot11 currently supports the following:
Decryption of WPA</br>
Decryption of WEP</br>
Encryption of WEP
</br></br>
### Prerequisites:
pyDot11 was built around scapy2.3.3 from PyPI.  Support and/or advice about pyDot11 requires the user have this version on their system.  For your convience, a local copy of scapy has been included in RESOURCEs/.  If you don't have scapy, or have a different version of scapy on your system, then feel free to use the locally included .tgz.  Directions for getting the local version up and running are as follows:
</br>
````bash
## From the pyDot11 folder run the following
tar zxf RESOURCEs/scapy-2.3.3.tgz
mv scapy-2.3.3/scapy/ .
rm -rf scapy-2.3.3/
````
</br>
### To get started: 
````bash
pip install pyDot11-0.5.2.tar.gz
python pyDot11 --help
````

### Various examples of other things you can do with pyDot11
````python
## Example of grabbing an encrypted packet, decrypting it, and then replaying it
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
## Example of taking a packet from Open Wifi, and then encrypting it
from pyDot11 import *
openPkts = rdpcap('PCAPs/ICMPs/open_pings.pcap')
openPkts[1].summary()
input = openPkts[1].__class__(str(openPkts[1])[0:-4])
encPkt = wepEncrypt(input, '0123456789')
encPkt.summary()
````

````python
## Example of decrypting a pcap file
from pyDot11 import *
decList = pcap.crypt2plain('PCAPs/ICMPs/wep_pings.pcap', '0123456789')
````
