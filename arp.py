from enum import Enum
from struct import pack, unpack
from typing import Tuple, Any, Union


class Index_In_Parsed_Tuple(Enum):
    """
    indexex in tuple of parsed arp data
    """
    SECOND_LAYER_TYPE_ADDR = 0
    THIRD_LAYER_TYPE_ADDR = 1
    LEN_SECOND_ADDR = 2
    LEN_THIRD_ADDR = 3
    OPCODE = 4
    SRC_MAC = 5
    SRC_IP = 6
    DST_MAC =7
    DST_IP = 8
    UNPACK_MODE = 9


OPCODE_INDEX = 6
OPCODE_VALUE_FOR_QUESTION = 1
OPCODE_VALUE_FOR_ANSWER = 2
UNPACK_TYPES_AND_LEN = "!HHbb"

def arp_handle(arp_protocol_data: bytes, my_ip) -> Union[bytes, None]:
    """
    handles arp protocol in frame
    :param arp_protocol_data: the arp protocol data
    :param my_ip: ip address of my computer in the interface we are sniffing from
    :return: if there is a response return the arp data of the response, else None
    """
    parsed_arp_protocol_data = parse_data(arp_protocol_data)
    if parsed_arp_protocol_data[Index_In_Parsed_Tuple.OPCODE.value] == OPCODE_VALUE_FOR_QUESTION and my_ip == parsed_arp_protocol_data[Index_In_Parsed_Tuple.DST_IP.value]:
        return pack_arp_data(parsed_arp_protocol_data, my_ip)

def pack_arp_data(parsed_data_arp_proto: Tuple[Any, Any, str, str, Any, Any, Any, Any, Any]) -> bytes:
    """
    packs arp protocol data for a response
    :param parsed_data_arp_proto: the parsed data from the question
    :return: the packed arp data response
    """
    arp_data = pack(f"{UNPACK_TYPES_AND_LEN}{parsed_data_arp_proto[Index_In_Parsed_Tuple.UNPACK_MODE.value]}",parsed_data_arp_proto[Index_In_Parsed_Tuple.SECOND_LAYER_TYPE_ADDR.value],parsed_data_arp_proto[Index_In_Parsed_Tuple.THIRD_LAYER_TYPE_ADDR.value], parsed_data_arp_proto[Index_In_Parsed_Tuple.LEN_SECOND_ADDR.value],parsed_data_arp_proto[Index_In_Parsed_Tuple.LEN_THIRD_ADDR.value], OPCODE_VALUE_FOR_ANSWER ,parsed_data_arp_proto[Index_In_Parsed_Tuple.DST_MAC.value],parsed_data_arp_proto[Index_In_Parsed_Tuple.DST_IP.value], parsed_data_arp_proto[Index_In_Parsed_Tuple.SRC_MAC.value], parsed_data_arp_proto[Index_In_Parsed_Tuple.SRC_IP.value])
    return arp_data

def parse_data(arp_protocol_data: bytes) -> Tuple[Any, Any, str, str, Any, Any, Any, Any, Any]:
    """
    parses arp protocol data
    :param arp_protocol_data: the data of the arp protocol
    :return: a tuple of the parsed data,  the indexing is explained here - Index_In_Parsed_Tuple
    """
    second_layer_type_addr, third_layer_type_addr, len_second_addr, len_third_addr =unpack(f"{UNPACK_TYPES_AND_LEN}", arp_protocol_data[:OPCODE_INDEX])
    s_len_second_addr, s_len_third_addr = str(len_second_addr), str(len_third_addr)
    unpack_mode = f"H{s_len_second_addr}s{s_len_third_addr}s{s_len_second_addr}s{s_len_third_addr}s"
    opcode_num, src_mac_address, src_ip_address, dst_mac_address, dst_ip_address = unpack(f"!{unpack_mode}", arp_protocol_data[:OPCODE_INDEX:])
    return (second_layer_type_addr, third_layer_type_addr, len_second_addr, len_third_addr,opcode_num, src_mac_address, src_ip_address, dst_mac_address, dst_ip_address, unpack_mode)
