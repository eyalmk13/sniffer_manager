from enum import Enum


class Types_protocols(Enum):
    ARP = 0x0806
    IPv4 = 0x0800
    NON_IDENTIFIED = 0


INDEX_START_TYPE = 12
INDEX_END_TYPE = 14


def third_layer_managment(data: bytes) -> None:
    """
    third_layer_manager
    :param data: data recieved from sniffer, the frame itself
    :return:
    """
    type_identity = identify_type_third_layer(data)
    if type_identity == Types_protocols.NON_IDENTIFIED:
        return
    data = data[INDEX_END_TYPE:]
    if type_identity == Types_protocols.IPv4:
        ipv4_manage(data)
    arp_manage(data)

def identify_type_third_layer(data: bytes) -> Types_protocols:
    """
    identify third layer protocol of the current frame
    :param data: data recieved from sniffer, the frame itself
    :return: the Types
    """
    type_data = data[INDEX_START_TYPE:INDEX_END_TYPE]
    if Types_protocols.ARP.value == type_data:
        return Types_protocols.ARP
    if Types_protocols.IPv4.value == type_data:
        return Types_protocols.IPv4
    return Types_protocols.NON_IDENTIFIED



def arp_manage(data: bytes) -> None:
    pass

def ipv4_manage(data: bytes) -> None:
    pass
