import argparse
from scapy.all import conf, get_if_hwaddr
from scapy.arch import get_if_addr
from ether_protocol import ethernet_handle


def sniffer(iface_index: int) -> None:
    """
    sniffs the packets arriving in a specific interface
    :param iface_index: the iface index in IFACES list to sniff from
    """
    iface = conf.ifaces.dev_from_index(iface_index)
    mac_address = get_if_hwaddr(iface)
    my_ip = get_if_addr(iface)
    sock = conf.L2socket(iface=iface, promisc=True)
    while True:
        _, payload, _= sock.recv_raw()
        if payload is not None:
            ethernet_handle(mac_address, payload, my_ip, sock)


def get_args():
    parser = argparse.ArgumentParser(description='raw data packet parser')
    parser.add_argument('iface_index', type=int,
                        help='iface index in IFACES list ')
    return parser.parse_args()


def main():
    args = get_args()
    sniffer(args.iface_index)


if __name__ == "__main__":
    main()
