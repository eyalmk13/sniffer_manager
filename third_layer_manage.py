from enum import Enum


class Types_Protocols(Enum):
    ARP = 0x0806
    IPv4 = 0x0800
    NON_IDENTIFIED = 0


INDEX_START_TYPE = 12
INDEX_END_TYPE = 14


def third_layer_management(data: bytes) -> None:
    """
    third_layer_manager
    :param data: data recieved from sniffer, the frame itself
    :return:
    """
    type_identity = identify_type_third_layer(data)
    if type_identity == Types_Protocols.NON_IDENTIFIED:
        return
    data = data[INDEX_END_TYPE:]
    if type_identity == Types_Protocols.IPv4:
        ipv4_manage(data)
        print("IPv4 data recieved")
    else:
        print("arp data recieved")
        arp_manage(data)


def identify_type_third_layer(data: bytes) -> Types_Protocols:
    """
    identify third layer protocol of the current frame
    :param data: data recieved from sniffer, the frame itself
    :return: the Types
    """

    type_data = int(data[INDEX_START_TYPE:INDEX_END_TYPE].hex(),16)
    if Types_Protocols.ARP.value == type_data:
        return Types_Protocols.ARP
    if Types_Protocols.IPv4.value == type_data:
        return Types_Protocols.IPv4
    return Types_Protocols.NON_IDENTIFIED



def arp_manage(data: bytes) -> None:
    pass

def ipv4_manage(data: bytes) -> None:
    pass
