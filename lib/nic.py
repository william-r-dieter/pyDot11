import fcntl, os, struct, subprocess

class Tap(object):
    """Handle the tap interface"""

    def __init__(self, tapNum = 0):
        self.tapName = 'tap' + str(tapNum)
        self.create()


    def create(self):
        """Create the tap interface"""
        self.nic = os.open('/dev/net/tun', os.O_RDWR)
        fcntl.ioctl(self.nic, 0x400454ca, struct.pack("16sH", self.tapName, 2))


    ### Not really needed
    #def send(self, pkt):
        #"""Send the packet in str format"""
        #os.write(self.nic, '\x00\x00\x00\x00' + pkt)