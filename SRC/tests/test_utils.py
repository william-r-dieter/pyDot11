import binascii
import unittest

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11QoS, RadioTap
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import *
from scapy.packet import Padding, Raw

import pyDot11.lib.utils as p11


class TestPacket(unittest.TestCase):
    """Test public methods the Packet class"""

    def setUp(self):
        self.pkt = RadioTap(version=0, pad=0, present=2686468138L, len=42,
                notdecoded=' \x08\x00\xa0 \x08\x00\x00\x10\x00<\x14@\x01\xc8\x00\x00\x00e\x00\x04\x04\x92\x00\x00\x00\x01\x00\x00\x00\xc6\x00\xc8\x01')\
            /Dot11(proto=0L, FCfield=2L, subtype=8L, SC=1248, type=2L, ID=11264,
                addr1='b8:08:cf:09:0a:8c',
                addr2='16:91:82:b6:62:15',
                addr3='16:91:82:b6:62:13',
                addr4=None)\
            /Dot11QoS(TID=0L, TXOP=0, Reserved=0L, EOSP=0L)\
            /LLC(dsap=170, ssap=170, ctrl=3)/SNAP(OUI=0, code=2048)\
            /IP(frag=0L, src='65.200.22.161', proto=6, tos=0,
                dst='192.168.3.140', chksum=38717, len=842, options=[],
                version=4L, flags=2L, ihl=5L, ttl=64, id=33747)\
            /TCP(reserved=0L, seq=2807109953, ack=2395100790, dataofs=8L,
                urgptr=0, window=3620, flags=24L, chksum=3646, dport=48728,
                sport=80, options=[('NOP', None), ('NOP', None),
                    ('Timestamp', (300784283, 225172108))])\
            /Raw(load="""\
HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nExpires: 0\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\n\r\n
<html>
  <head>
    <noscript>
      <meta http-equiv=Refresh Content="0; URL=http://192.168.3.1:10080/ui/dynamic/guest-login.html">
    </noscript>
    <script language=\'javascript\' type=\'text/javascript\'>function init(_frm) { if (_frm.sent.value == 0) { _frm.sent.value=1; _frm.submit(); } }</script>
  </head>
  <body onload=init(auth)>
    <form name=authaction=\'http://192.168.3.1:10080/ui/dynamic/guest-login.html\' METHOD=GET>
      <input type=hidden name=\'mac_addr\' value=\'b8:08:cf:09:0a:8c\'>
      <input type=hidden name=\'url\' value=\'http://detectportal.firefox.com/success.txt\'>
      <input type=hidden name=\'ip_addr\' value=\'192.168.3.140\'>
      <input type=hidden id=sent value=\'0\'>
    </form>
  </body>
</html>""")\
            /Padding(load='\x95\x07\xd6\xd4')

    def test_fcsGenIntOutput(self):
        expected = 0xcd925e20
        pd11pkt = p11.Packet()
        actual = pd11pkt.fcsGen(self.pkt[Dot11], end = -4, output = 'int')
        self.assertEqual(expected, actual,
                         'expected 0x{:08x}, but got 0x{:08x}'
                         .format(expected, actual))

    def test_fcsGenByteOutput(self):
        expected = '205e92cd'
        pd11pkt = p11.Packet()
        actual = pd11pkt.fcsGen(self.pkt[Dot11], end = -4, output = 'bytes')
        self.assertEqual(expected, actual,
                         'expected "{:8s}", but got "{:8s}"'
                         .format(expected, actual))

    def test_fcsGenStringOutput(self):
        expected = '\x20\x5e\x92\xcd'
        expected_str = binascii.hexlify(expected)
        pd11pkt = p11.Packet()
        actual = pd11pkt.fcsGen(self.pkt[Dot11], end = -4, output = 'str')
        actual_str = binascii.hexlify(actual)
        self.assertEqual(expected, actual,
                         'expected "{:8s}", but got "{:8s}"'
                         .format(expected_str, actual_str))


if __name__ == "__main__":
    unittest.main()
