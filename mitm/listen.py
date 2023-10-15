#!/usr/bin/python3
#conding:utf-8

from scapy.all import IP, Ether, ARP, srp1, sniff
from scapy.layers.http import HTTPRequest
import sys, time, json
from datetime import datetime

def http(ip, nb):
    if len(sys.argv) != 3:
        print("Arguments manquants. Deux arguments sont attendus !")
        exit()


    client_request  = Ether() / ARP(pdst=ip)
    client_response = srp1(client_request, timeout=5)

    if client_response is None:
        print("Client unreachable !")
        exit()

    result = []

    def check(package):
        if HTTPRequest in package and package[IP].src == ip:
            request = package[HTTPRequest]
            record = {
                    "Date_time" : str(datetime.now()),
                    "Server_ip" : package[IP].dst,
                    "Method"    : request.Method.decode(utf-8),
                    "URI"       : request.Path.decode(utf-8)
                }
            result.append(record)

            print("{},{},{},{}".format(
                record["Date_time"],
                record["Server_ip"],
                record["Method"],
                record["URI"]
            ))


    sniff(prn=check, timeout=int(nb), iface="enp0s3")

    with open('capture.json', 'W') as file:
        json.dump(result, file, indent=4)

http(sys.argv[1], sys.argv[2])
