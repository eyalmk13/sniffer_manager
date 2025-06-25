from third_layer_manage import third_layer_managment

DST_MAC_END_INDEX = 6
BLANK_STR = ""
BROADCAST_MAC_ADDR = "ffffffffffff"

def ethernet_management(mac_address: str, data: bytes) -> None:
    """
    ethernet layer management
    :param mac_address: mac address of our computer
    :param data: data recieved from sniffer, the frame itself
    """
    if check_dst_mac(mac_address, data):
        third_layer_managment(data)


def check_dst_mac(mac: str, recieved_message: bytes) -> bool:
    """
    checks if the frame was conducted to us
    :param mac: mac address of our computer
    :param recieved_message: data recieved from sniffer, the frame itself
    :return: True if the frame was conducted to us else False
    """
    dst_mac_packet = recieved_message[:DST_MAC_END_INDEX].hex()
    mac_without_colon = mac.replace(":", BLANK_STR)
    return dst_mac_packet == mac_without_colon or dst_mac_packet == BROADCAST_MAC_ADDR

