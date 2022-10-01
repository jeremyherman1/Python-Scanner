#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()
print("Welcome to an nmap automation tool")

ip_addr = input("Please type the IP Address you want to scan: ")
print("The IP Address you entered is", ip_addr)
type(ip_addr)

resp = input(""" \nPlease enter the type of scan you want to run
                  1) SYN ACK Scan
                  2) UDP Scan
                  3) Comprehensive Scan \n""")
print("You have selected option: ", resp)  

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())