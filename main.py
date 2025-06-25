import argparse
from scapy.all import conf, get_if_hwaddr
from scapy.arch import get_if_addr

from ether_layer import ethernet_management

DATA_INDEX = 1


def sniffer_manager(iface_index: int) -> None:
    """
    sniff manager
    :param iface_index: the iface index in IFACES list to sniff from
    """
    try:
        iface = conf.ifaces.dev_from_index(iface_index)
    except ValueError:
        print("Invalid interface index")
        return
    mac_address = get_if_hwaddr(iface)
    my_ip = get_if_addr(iface)
    sock = conf.L2socket(iface=iface, promisc=True)
    while True:
        recv = sock.recv_raw()
        if recv != (None, None, None):
            ethernet_management(mac_address, recv[DATA_INDEX], my_ip, sock)




def get_args():
    parser = argparse.ArgumentParser(description='raw data packet parser')
    parser.add_argument('iface_index', type=str,
                        help='iface index in IFACES list ')
    return parser.parse_args()


def main():
    args = get_args()
    sniffer_manager(args.iface_index)


if __name__ == "__main__":
    main()