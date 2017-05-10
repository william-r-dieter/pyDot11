# pyDot11

## pyDot11 currently supports the following:
Decryption of WPA</br>
Decryption of WEP</br>
Encryption of WEP
</br></br>
### Prerequisites:
pyDot11 has requirements that require planning before usage.  The easiest way to deal with those is first ask the user, which interpreter they want to use.  As you know, Python is an interpreted language, and as such can be slower than a compiled language.  A workaround to this is to use something like PyPy.  There are many paths which lead to the same goal, but in the attempt at keeping things simple, only two setups will be supported.
<br><br>
It is essential to note before moving on that pyDot11 was built around scapy2.3.3 from PyPI.  Support and/or advice about pyDot11 requires the user have this version on their system.  If you don't have scapy, or have a different version of scapy on your system, then feel free to use the locally included module.
<br><br>
Setup #1 - Python
        
In the RESOURCEs folder you will find the python modules which have been tested.  As newver versions of the modules come out, sufficient testing must be done before they can be made known as "stable" with pyDot11.  Feel free to use pip or whatever method you would like to get these installed.  If you wish to use the modules locally provided with this git, then an installation would be something like so:
````bash
pip install RESOURCEs/pbkdf2-1.3.tar.gz
pip install RESOURCEs/pyDot11-0.6.1.tar.gz
pip install RESOURCEs/pycryptodomex-3.4.5.tar.gz
pip install RESOURCEs/rc4-0.1.tar.gz
pip install RESOURCEs/scapy-2.3.3.tgz

## If you run into issues with the scapy module not being found
## Try this workaround
tar zxf RESOURCEs/scapy-2.3.3.tgz
mv scapy-2.3.3/scapy/ .
rm -rf scapy-2.3.3/
````
<br><br>
Setup #2 - PyPy

While using something such as virtualenv would achieve the desired outcome, the logic for avoiding the need has been baked into pyDot11 by modifying sys.path and uing _PYPY as the parent folder for the PyPy modules.  Of the modules needed, pycryptodomex requires compilation by pypy itself.  Every other module can simply be installed to the _PYPY folder.  Directions are as such:
````bash
## From the pyDot11 folder run the folder
pip install RESOURCEs/pyDot11-0.6.2.tar.gz -t _PYPY
pip install RESOURCEs/pbkdf2-1.3.tar.gz -t _PYPY
pip install RESOURCEs/rc4-0.1.tar.gz -t _PYPY
pip install RESOURCEs/scapy-2.3.3.tgz -t _PYPY
tar zxf RESOURCEs/pycryptodomex-3.4.5.tar.gz -C _PYPY
cd _PYPY/pycryptodomex-3.4.5/ && pypy setup.py build && mv build/lib*/Cryptodome ../ && cd ../../ && rm -rf _PYPY/pycryptodomex-3.4.5/
````
### To get started: 
````bash
## From the pyDot11 folder run the following
python pyDot11 --help
 -or-
pypy pyDot11 --help
````
### Need help grabbing an EAPOL?
````bash
## From the pyDot11 folder run the following
python airpunt --help
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
