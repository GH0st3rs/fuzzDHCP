#!/usr/bin/python
import socket
import struct
from random import randint
import fcntl
import sys
import binascii
from argparse import ArgumentParser
import serial

# From /usr/include/linux/if_ether.h
ETH_P_IP = 0x0800
DEFAULT_DHCP_CLIENT_PORT = 68
DEFAULT_DHCP_SERVER_PORT = 67
DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8


def parge_args():
    parser = ArgumentParser(description='DHCP Fuzzer')
    parser.add_argument('-i', dest='iface', required=True, help='Select source interface')
    parser.add_argument('-j', dest='log', action='store_true', help='Enable logging (default: False)', default=False)
    return parser.parse_args()


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15].encode()))
    return info[18:24]


def macToStr(data):
    return ':'.join(['%02x' % ord(char) for char in data])


def strToMac(data):
    mac = b''
    for x in data.split(':'):
        mac += chr(int(x, 16)).encode()
    return mac


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


class DHCPPacket(UDP):
    def __init__(self, iface, client=True, ptype=DHCPDISCOVER, **kwargs):
        super(DHCPPacket, self).__init__(
            sport=kwargs.pop('sport'),
            dport=kwargs.pop('dport'),
            **kwargs
        )
        self.iface = iface
        self.msg_type = ptype
        self.op = 1 if client else 2
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
        self.chaddr = getHwAddr(self.iface).ljust(16, b'\xff')
        # self.chaddr = strToMac('00:10:18:00:00:01').ljust(16, b'\xff')
        self.sname = rand_string(64)
        self.file = rand_string(128)
        self.options_magic = b'\x63\x82\x53\x63'

    def craftPacket(self, index):
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
        self.raw += self.craftOptions(index)
        return super(DHCPPacket, self).craftPacket(self.raw)

    def craftOptions(self, index):
        code = index
        length = rand_byte() if index != 60 else 120
        value = b'A' * 255
        print('Options:\nCode: %d\nLength: %d\nValue: (%d) %s\n' % (code, length, len(value), binascii.hexlify(value)))
        self.options = struct.pack('!BBB', 53, 1, self.msg_type)  # Message type
        self.options += struct.pack('!BB255s', code, length, value)  # option
        self.options += struct.pack('!B', 255)  # [END]
        return self.options


def logger(s):
    data = s.read(4096)
    if 'SigHandler' in data:
        dump = s.read_until('HELO')
        return (False, data + dump)
    return (True, None)


def sender(src_iface, index):
    # defining the socket
    dhcps = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))  # internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # buiding and sending the DHCP packet
    dhcpPacket = DHCPPacket(
        iface=src_iface,
        sport=DEFAULT_DHCP_CLIENT_PORT,
        dport=DEFAULT_DHCP_SERVER_PORT,
        src_ip='0.0.0.0',
        dst_ip='255.255.255.255',
        client=True,
        ptype=DHCPDISCOVER
    )
    data = dhcpPacket.craftPacket(index)
    log('XID: %d\nOptions: %s\nPacket: %s' % (
        dhcpPacket.xid,
        binascii.hexlify(dhcpPacket.options),
        binascii.hexlify(data)
    ))
    dhcps.sendto(data, (src_iface, ETH_P_IP, 0, 0, b'\xFF' * 6))

    print('\nDHCP Discover sent waiting for reply...')
    # receiving DHCPOffer packet
    dhcps.settimeout(2)
    # try:
    #     while True:
    #         data = dhcps.recv(1024)[28:]
    #         received_xid = struct.unpack('I', data[4:8])[0]
    #         if dhcpPacket.xid == received_xid:
    #             print('DHCPOffer receied: %d' % dhcpPacket.xid)
    #             break
    # except socket.timeout as e:
    #     print(e)
    dhcps.close()  # we close the socket
    return data


def log(data):
    print('Log: %s' % data)
    with open('request.log', 'a+') as f:
        splitter = '\n' + '-' * 100 + '\n'
        f.write(splitter)
        f.write(data)
        f.write(splitter)


def crashLog(data):
    with open('crashes.log', 'a+') as f:
        splitter = '\n' + '-' * 100 + '\n'
        f.write(splitter)
        f.write(data)
        f.write(splitter)


if __name__ == '__main__':
    args = parge_args()
    s = serial.Serial('/dev/buspirate', 115200, timeout=4)
    for x in range(255):
        data = sender(args.iface, x)
        if args.log:
            status, dump = logger(s)
            if not status:
                print('Reboot')
                crashLog('Request: %s\n\n%s' % (binascii.hexlify(data), dump))
                break
