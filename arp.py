from enum import Enum
from struct import pack, unpack
from typing import Tuple, Any

from ether_layer import ether_layer_send
from third_layer_manage import INDEX_END_TYPE_ETHER, Types_Protocols


class Index_In_Parsed_Tuple(Enum):
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

def arp_manage(data: bytes, sock, my_ip) -> None:
    parsed_data = parse_data(data)
    if parsed_data[Index_In_Parsed_Tuple.OPCODE.value] == OPCODE_VALUE_FOR_QUESTION  :
        send_arp(parsed_data, sock, my_ip)



def send_arp(parsed_data: tuple[Any, Any, str, str, Any, Any, Any, Any, Any], sock, my_ip) -> None:
    arp_data = pack(f"{UNPACK_TYPES_AND_LEN}{parsed_data[Index_In_Parsed_Tuple.UNPACK_MODE.value]}",parsed_data[Index_In_Parsed_Tuple.SECOND_LAYER_TYPE_ADDR.value],parsed_data[Index_In_Parsed_Tuple.THIRD_LAYER_TYPE_ADDR.value], parsed_data[Index_In_Parsed_Tuple.LEN_SECOND_ADDR.value],parsed_data[Index_In_Parsed_Tuple.LEN_THIRD_ADDR.value], OPCODE_VALUE_FOR_ANSWER ,parsed_data[Index_In_Parsed_Tuple.DST_MAC.value],my_ip, parsed_data[Index_In_Parsed_Tuple.SRC_MAC.value], parsed_data[Index_In_Parsed_Tuple.SRC_IP.value])
    ether_layer_send(Types_Protocols.ARP.value, parsed_data[Index_In_Parsed_Tuple.DST_MAC.value], parsed_data[Index_In_Parsed_Tuple.SRC_MAC.value], sock, arp_data)


def parse_data(data: bytes) -> tuple[Any, Any, str, str, Any, Any, Any, Any, Any]:
    second_layer_type_addr, third_layer_type_addr, len_second_addr, len_third_addr =unpack(f"{UNPACK_TYPES_AND_LEN}", data[INDEX_END_TYPE_ETHER: INDEX_END_TYPE_ETHER + OPCODE_INDEX])
    s_len_second_addr, s_len_third_addr = str(len_second_addr), str(len_third_addr)
    unpack_mode = f"H{s_len_second_addr}s{s_len_third_addr}s{s_len_second_addr}s{s_len_third_addr}s"
    opcode_num, src_mac_address, src_ip_address, dst_mac_address, dst_ip_address = unpack(f"!{unpack_mode}", data[INDEX_END_TYPE_ETHER + OPCODE_INDEX:])
    return (second_layer_type_addr, third_layer_type_addr, len_second_addr, len_third_addr,opcode_num, src_mac_address, src_ip_address, dst_mac_address, dst_ip_address, unpack_mode)
