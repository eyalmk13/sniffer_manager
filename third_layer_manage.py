from enum import Enum
from arp import arp_manage



class Types_Protocols(Enum):
    ARP = 0x0806
    IPv4 = 0x0800
    NON_IDENTIFIED = 0


INDEX_START_TYPE_ETHER = 12
INDEX_END_TYPE_ETHER = 14


def third_layer_management(data: bytes, my_ip: str, sock) -> None:
    """
    third_layer_manager
    :param data: data recieved from sniffer, the frame itself
    :return:
    """
    type_identity = identify_type_third_layer(data)
    if type_identity == Types_Protocols.NON_IDENTIFIED:
        return
    data = data[INDEX_END_TYPE_ETHER:]
    if type_identity == Types_Protocols.IPv4:
        ipv4_manage(data)
        print("IPv4 data recieved")
    else:
        print("arp data recieved")
        arp_manage(data, sock, my_ip)


def identify_type_third_layer(data: bytes) -> Types_Protocols:
    """
    identify third layer protocol of the current frame
    :param data: data recieved from sniffer, the frame itself
    :return: the Types
    """

    type_data = int(data[INDEX_START_TYPE_ETHER:INDEX_END_TYPE_ETHER].hex(),16)
    if Types_Protocols.ARP.value == type_data:
        return Types_Protocols.ARP
    if Types_Protocols.IPv4.value == type_data:
        return Types_Protocols.IPv4
    return Types_Protocols.NON_IDENTIFIED

def ipv4_manage(data: bytes) -> None:
    pass
