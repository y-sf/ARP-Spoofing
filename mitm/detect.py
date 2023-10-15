#!/usr/bin/python3
#coding:utf-8

from scapy.all import ARP, sniff

ip_mac_dict = {}    

def process_packet(packet):
    if packet.haslayer(ARP):            
        if packet[ARP].op == 2:          
            print("ARP Response detected from IP: " + packet[ARP].psrc + " MAC: " + packet[ARP].hwsrc)

            if packet[ARP].psrc in ip_mac_dict:       
                if ip_mac_dict[packet[ARP].psrc] != packet[ARP].hwsrc:
                    print("ARP poisoning detected from IP: " + packet[ARP].psrc + " MAC: " + packet[ARP].hwsrc)
            else:
                ip_mac_dict[packet[ARP].psrc] = packet[ARP].hwsrc           

sniff(prn=process_packet, filter="arp", store=0)   
