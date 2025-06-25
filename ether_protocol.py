from struct import pack, unpack
from enum import Enum


class Types_Protocols(Enum):
    """
    values of these protocols in the header type of ethernet packets
    """
    ARP = 0x0806
    IPv4 = 0x0800
    NON_IDENTIFIED = 0


INDEX_END_ETHER_PROTOCOL = 14
BROADCAST_MAC_ADDR = "ffffffffffff"
PACK_MODE = "!6s6sH"


def ethernet_handle(mac_address: str, frame_data: bytes, my_ip, sock) -> None:
    """
    handles frame with protocol ethernet
    :param mac_address: mac address of my computer in the interface we are sniffing from
    :param frame_data: the frame data
    :param my_ip: ip address of my computer in the interface we are sniffing from
    :param sock: socket of interface to send/recieve data
    """
    dst_mac,src_mac, type_next_protocol = unpack(PACK_MODE, frame_data[:INDEX_END_ETHER_PROTOCOL])
    if check_dst_mac(mac_address, dst_mac.hex()):
        handle_next_protocol(type_next_protocol, frame_data[INDEX_END_ETHER_PROTOCOL:], my_ip, sock)


def check_dst_mac(mac: str, dst_mac_of_frame: str) -> bool:
    """
    checks if the frame was conducted to us
    :param mac: mac address of our computer
    :param dst_mac_of_frame: destination mac address of frame
    :return: True if the frame was conducted to us else False
    """
    mac_without_colon = mac.replace(":", "")
    return dst_mac_of_frame == mac_without_colon or dst_mac_of_frame == BROADCAST_MAC_ADDR

def ether_protocol_send(type_next_protocol: int, my_mac: str, dst_mac: str, sock, next_protocol_data: bytes) -> None:
    """
    sends frame with protocol ethernet
    :param type_next_protocol: the type of next protocol in frame
    :param my_mac: mac address of my computer in the interface we are sniffing from
    :param dst_mac: destination mac address of frame
    :param sock: socket of interface to send/recieve data
    :param next_protocol_data: Payload data from the next protocol
    :return:
    """
    ether_protocol_headers = pack(f"{PACK_MODE}", dst_mac,  my_mac,type_next_protocol)
    sock.send(ether_protocol_headers + next_protocol_data)


def handle_next_protocol(type_next_protocol: int, next_protocol_data: bytes, my_ip, sock) -> None:
    """
    handles next protocol in frame
    :param type_next_protocol:  the type of next protocol in frame
    :param next_protocol_data: Payload data from the next protocol
    :param my_ip: ip address of my computer in the interface we are sniffing from
    :param sock: socket of interface to send/recieve data
    """
    type_identity = identify_next_protocol(type_next_protocol)
    if type_identity == Types_Protocols.NON_IDENTIFIED:
        return
    if type_identity == Types_Protocols.IPv4:
        ipv4_handle(next_protocol_data, sock, my_ip)
    else:
        arp_handle(next_protocol_data,sock,my_ip)


def identify_next_protocol(type_next_protocol: int) -> Types_Protocols:
    """
    identify next protocol in frame
    :param type_next_protocol: the type of next protocol in frame
    :return: the instance of next protocol in class Types_Protocols
    """
    if Types_Protocols.ARP.value == type_next_protocol:
        return Types_Protocols.ARP
    if Types_Protocols.IPv4.value == type_next_protocol:
        return Types_Protocols.IPv4
    return Types_Protocols.NON_IDENTIFIED

def ipv4_handle(data_starting_from_ipv4: bytes, sock, my_ip: str) -> None:
    pass
def arp_handle(data_starting_from_arp: bytes, sock, my_ip: str) -> None:
    pass
