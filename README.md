# pyDot11

## pyDot11 currently supports the following:
* Decryption of WPA
* Encryption of WPA
    ** CCMP only for now
* Decryption of WEP
* Encryption of WEP

### Prerequisites:
There are some conflicts using scapy-2.3.3.  For now, until those issues are worked out, please use the 2.2.0 version.  Feel free to use the 2.2.0 version from our library, or one of your own choosing.
<br><br>

### Setup:
        
In the RESOURCEs folder you will find the python modules which have been tested.  As newver versions of the modules come out, sufficient testing must be done before they can be made known as "stable" with pyDot11.  Feel free to use pip or whatever method you would like to get these installed.  If you wish to use the modules locally provided with this git, then an installation would be something like so:
````bash
pip install RESOURCEs/pbkdf2-1.3.tar.gz
pip install RESOURCEs/pyDot11-1.0.8.tar.gz
pip install RESOURCEs/pycryptodomex-3.4.5.tar.gz
pip install RESOURCEs/rc4-0.1.tar.gz
pip install RESOURCEs/scapy_2.2.0.orig.tar.gz

## If you run into issues with the scapy module not being found
## Try this local folder workaround
tar zxf RESOURCEs/scapy_2.2.0.orig.tar.gz
mv scapy-2.2.0/scapy/ .
rm -rf scapy-2.2.0/
````
<br><br>

### To get started: 
````bash
## From the pyDot11 folder run the following
python pyDot11 --help
WEP Example: python pyDot11 -i wlan0mon -p <password> -b <tgt BSSID> -t wep
WPA Example: python pyDot11 -i wlan0mon -p <password> -b <tgt BSSID> -t wpa -e <tgt ESSID>
    ## OR ##
pypy pyDot11 --help
WEP Example: pypy pyDot11 -i wlan0mon -p <password> -b <tgt BSSID> -t wep -o pypy
WPA Example: pypy pyDot11 -i wlan0mon -p <password> -b <tgt BSSID> -t wpa -e <tgt ESSID> -o pypy
````
### Need help grabbing an EAPOL?
````bash
## From the pyDot11 folder run the following:
python scripts/airpunt --help
````
### Various examples of other things you can do with pyDot11:
<strong>We can <a href="https://github.com/ICSec/airpwn-ng">airpwn-ng!</href></strong>
````python
## Example of grabbing an encrypted packet, decrypting it, and then replaying it:
from pyDot11 import *
from scapy.utils import rdpcap
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
## Example of taking a packet from Open Wifi, and then encrypting it:
from pyDot11 import *
from scapy.utils import rdpcap
openPkts = rdpcap('PCAPs/ICMPs/open_pings.pcap')
openPkts[1].summary()
input = openPkts[1].__class__(str(openPkts[1])[0:-4])
encPkt = wepEncrypt(input, '0123456789')
encPkt.summary()
````

````python
## Example of decrypting a WEP pcap file:
from pyDot11 import *
decList = pcap.crypt2plain('PCAPs/ICMPs/wep_pings.pcap', 'WEP', '0123456789')
decPcap = PcapWriter('decrypted_pings.pcap', sync = True)
for i in decList:
    decPcap.write(i)
````
