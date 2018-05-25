#!/usr/bin/python
import socket
import struct
from random import randint
import fcntl
import sys


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15].encode()))
    return info[18:24]


def macToStr(data):
    return ':'.join(['%02x' % ord(char) for char in data])


def rand_byte():
    return randint(0, 0xFF)


def rand_word():
    return randint(0, 0xFFFF)


def rand_qword():
    return randint(0, 0xFFFFFFFF)


def rand_string(size):
    txt = b''
    while len(txt) != size:
        txt += chr(randint(0, 0xFF))
    return txt


class IPv4(object):
    """Create an IPv4 packet."""

    def __init__(self, src_ip, dst_ip, proto, **kwargs):
        self.ip_saddr = socket.inet_aton(src_ip)
        self.ip_daddr = socket.inet_aton(dst_ip)
        self.ip_proto = proto
        self.IP_HEADER_LEN = 20
        # ---- [Internet Protocol Version] ---
        ip_ver = 4
        ip_vhl = 5
        self.ip_ver = (ip_ver << 4) + ip_vhl
        # ---- [ Differentiate Servic Field ]
        ip_dsc = 0
        ip_ecn = 0
        self.ip_dfc = (ip_dsc << 2) + ip_ecn
        # ---- [ Total Length]
        self.ip_tol = 0
        # ---- [ Identification ]
        self.ip_idf = 1
        # ---- [ Flags ]
        ip_rsv = 0
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0
        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)
        # ---- [ Total Length ]
        self.ip_ttl = 64
        # ---- [ Check Sum ]
        self.ip_chk = 0

    def checksum(self, data):
        checksum = 0
        data_len = len(data)
        if (data_len % 2) == 1:
            data_len += 1
            data += struct.pack('!B', 0)
        if sys.version < '3':
            data = [ord(x) for x in data]
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            checksum += w
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        return ~checksum & 0xFFFF

    def craftPacket(self, payload):
        self.ip_tol = self.IP_HEADER_LEN + len(payload)
        self.raw = struct.pack('!BBHHHBB',
                               self.ip_ver,   # IP Version
                               self.ip_dfc,   # Differentiate Service Feild
                               self.ip_tol,   # Total Length
                               self.ip_idf,   # Identification
                               self.ip_flg,   # Flags
                               self.ip_ttl,   # Time to leave
                               self.ip_proto,  # protocol
                               )
        self.ip_chk = self.checksum(self.raw)
        self.raw += struct.pack('!H4s4s',
                                self.ip_chk,   # Checksum
                                self.ip_saddr,  # Source IP
                                self.ip_daddr  # Destination IP
                                )
        return self.raw + payload


class UDP(IPv4):
    """Create a UDP packet."""

    def __init__(self, sport, dport, **kwargs):
        super(UDP, self).__init__(
            src_ip=kwargs.pop('src_ip'),
            dst_ip=kwargs.pop('dst_ip'),
            proto=socket.IPPROTO_UDP
        )
        self.sport = sport
        self.dport = dport
        self.length = 0
        self.udp_chk = 0
        self.UDP_HEADER_LEN = 8

    def craftPacket(self, payload):
        self.length = self.UDP_HEADER_LEN + len(payload)
        self.raw = struct.pack('!HHH',
                               self.sport,   # Source port
                               self.dport,   # Destination port
                               self.length,   # Total Length
                               )
        self.udp_chk = self.checksum(
            self.ip_saddr +
            self.ip_daddr +
            struct.pack('>H', self.ip_proto) +
            struct.pack('>H', self.length) +
            self.raw +
            payload
        )
        self.raw += struct.pack('>H', self.udp_chk) + payload
        return super(UDP, self).craftPacket(self.raw)

        
class DHCPDiscover(UDP):
    def __init__(self, iface, **kwargs):
        super(DHCPDiscover, self).__init__(
            sport=kwargs.pop('sport'),
            dport=kwargs.pop('dport'),
            **kwargs
        )
        self.iface = iface
        self.op = 1
        self.htype = 1
        self.hlen = 6
        self.hops = 0
        self.xid = rand_qword()
        self.secs = 0
        self.flags = 0
        self.ciaddr = rand_qword()
        self.yiaddr = rand_qword()
        self.siaddr = rand_qword()
        self.giaddr = rand_qword()
        self.chaddr = getHwAddr(self.iface).ljust(16, b'\x00')
        self.sname = rand_string(64)
        self.file = rand_string(128)
        self.options_magic = b"\x63\x82\x53\x63"

    def craftPacket(self):
        self.raw = struct.pack('BBBBIHHIIII16s64s128s4s',
                               self.op,  # Message type: Boot Request (1)
                               self.htype,  # Hardware type: Ethernet
                               self.hlen,  # Hardware address length: 6
                               self.hops,  # Hops: 0
                               self.xid,  # Transaction ID
                               self.secs,  # Seconds elapsed: 0
                               self.flags,  # Bootp flags: 0x8000 (Broadcast) + reserved flags
                               self.ciaddr,  # Client IP address: 0.0.0.0
                               self.yiaddr,  # Your (client) IP address: 0.0.0.0
                               self.siaddr,  # Next server IP address: 0.0.0.0
                               self.giaddr,  # Relay agent IP address: 0.0.0.0
                               self.chaddr,  # Client MAC address: 00:01:02:03:04:05
                               self.sname,  # Server host name not given
                               self.file,  # Boot file name not given
                               self.options_magic,  # Magic cookie: DHCP
                               )
        # Options
        options = b"\x35\x01\x01"
        options += struct.pack('!B', 60) + struct.pack('!B', rand_byte()) + rand_string(255)
        options += struct.pack('!B', 255)
        self.raw += options
        return super(DHCPDiscover, self).craftPacket(self.raw)


class DHCPOffer:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.nextServerIP = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime = ''
        self.router = ''
        self.subnetMask = ''
        self.DNS = []
        self.unpack()

    def unpack(self):
        if self.data[4:8] == self.transID:
            self.offerIP = '.'.join(map(lambda x: str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x: str(x), data[20:24]))  # c'est une option
            self.DHCPServerIdentifier = '.'.join(map(lambda x: str(x), data[245:249]))
            self.leaseTime = str(struct.unpack('!L', data[251:255])[0])
            self.router = '.'.join(map(lambda x: str(x), data[257:261]))
            self.subnetMask = '.'.join(map(lambda x: str(x), data[263:267]))
            # print self.router, self.subnetMask, self.leaseTime, self.DHCPServerIdentifier, repr(self.offerIP)
            print(repr(data))
            print(repr(data[268]))
            dnsNB = int(data[268] / 4)
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append('.'.join(map(lambda x: str(x), data[269 + i:269 + i + 4])))

    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address', 'subnet mask', 'lease time (s)', 'default gateway']
        val = [self.DHCPServerIdentifier, self.offerIP, self.subnetMask, self.leaseTime, self.router]
        for i in range(4):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))

        print('{0:20s}'.format('DNS Servers') + ' : ', )  # end=''   here also have error.
        if self.DNS:
            print('{0:15s}'.format(self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)):
                print('{0:22s} {1:15s}'.format(' ', self.DNS[i]))


def sender():
    # defining the socket
    dhcps = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))  # internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # buiding and sending the DHCPDiscover packet
    discoverPacket = DHCPDiscover(iface='enp2s0', sport=68, dport=67, src_ip='0.0.0.0', dst_ip='255.255.255.255')
    dhcps.sendto(discoverPacket.craftPacket(), ('enp2s0', 0x0800, 0, 0, b'\xFF' * 6))

    print('\nDHCP Discover sent waiting for reply...')
    # receiving DHCPOffer packet
    dhcps.settimeout(2)
    try:
        while True:
            data = dhcps.recv(1024)[28:]
            received_xid = struct.unpack('I', data[4:8])[0]
            if discoverPacket.xid == received_xid:
                print('DHCPOffer receied: %d' % discoverPacket.xid)
                break
    except socket.timeout as e:
        print(e)
    dhcps.close()  # we close the socket


if __name__ == '__main__':
    for x in range(100):
        sender()
