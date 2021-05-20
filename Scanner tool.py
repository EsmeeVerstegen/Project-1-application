#import files
import time #for time pauses
import sys #for restart function
import socket #for port scanner
from scapy.all import ARP, Ether, srp #for mac address scanner
import ipaddress #ip address validation
import os

#systeem scanner
import psutil
import platform
from datetime import datetime

#start application
def start():
    print()
    print("######## WELCOME TO MY SCANNER APPLICATION ########")
    print("*** MAIN MENU ***")
    print("choose 1: for remote scans")
    print("choose 2: for local scans")
    print("choose 3: to exit the application")
    menu_choice = input("What kind of scan do you want to execute? (only type the number of your choice):    ")
    if(menu_choice == "1"):
        menu_1()

    if(menu_choice == "2"):
        menu_2()

    if(menu_choice == "3"):
        sys.exit()

    else:
        print("Error! You didn't type one of the numbers listed above, Please try again.")
        return start()
    
#REMOTE scan menu
def menu_1():
    print()
    print("*** REMOTE SCAN MENU ***")
    print("Here is a list with scans you can execute remotely:")
    print("choose 1: scan for mac addresses on your network")
    print("choose 2: ")
    print("choose 3: go back to the main menu")
    scan_remote = input("What remote scan do you want to execute? (only type the number of your choice):    ")
    if(scan_remote == "1"):
        print()
        print("*** MAC ADDRESS SCANNER ***")
        time.sleep(2)
        mac_addr_scanner()
    
    if(scan_remote == "2"):
        print()
        print("*** WEBSITE SCANNER ***")
        time.sleep(2)
        website_scanner()
        
    if(scan_remote == "3"):
        print()
        print("*** Returning to the main menu ***")
        time.sleep(2)
        return start()

    else:
        print("Error! You didn't type one of the numbers listed above, Please try again.")
        print()
        time.sleep(2)
        return menu_1()

#remote function 1
def mac_addr_scanner():
    while True:
        target_ip = input("Type your target ip here:    ")
        try:
            ip_scan = ipaddress.ip_address(target_ip)
            print("Valid ip, you may continue.")
            break
        except:
            print("IP address invalid, please try again.")

    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0) [0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

    print("WARNING! If there is no IP and/or MAC address it means that your target doesn't exist in your current network")
    try_over = input("Would you like to try another ip? please type yes or no.")
    if(try_over == "yes") or (try_over == "y") or (try_over == "YES") or (try_over == "Y"):
        print()
        time.sleep(1)
        return mac_addr_scanner()
    
    if(try_over == "no") or (try_over == "n") or (try_over == "NO") or (try_over == "N"):
        print("*** Continuing the program ***")
        time.sleep(2)
        print()
        return restart()

#Remote function 2
def website_scanner():
    domain_name = input("Please type the domain name of your target (example.com):    ")
    domain_addres = socket.gethostbyname(domain_name)
    print("IP Address is: " + domain_addres)

    for port in range(20, 8080):      #check for all available ports
        try:
            serv = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # create a new socket
            serv.bind((domain_addres,port)) # bind socket with address
             
        except:
            print('[OPEN] Port open :',port) #print open port number
            
        serv.close() #close connection
print("done")

#LOCAL scan menu
def menu_2():
    print()
    print("*** LOCAL SCAN MENU ***")
    print("Here is a list with scans you can execute locally:")
    print("choice 1: port scanner")
    print("choice 2: system information scanner")
    print("choice 3: network information scanner")
    print("choice 4: ")
    print("choose 5 to go back to the main menu")
    scan_local = input("What scan do you want to execute? (only type the number of your choice):    ")
    if(scan_local == "1"):
        print()
        print("*** PORT SCANNER ***")
        time.sleep(2)
        port_scanner()

    if(scan_local == "2"):
        print()
        print("*** SYSTEM SCANNER ***")
        time.sleep(2)
        system_scanner()

    if(scan_local == "3"):
        print()
        print("*** NETWORK SCANNER ***")
        time.sleep(2)
        network_info_scanner()

    if(scan_local == "4"):
        print()
        print("")
        time.sleep(2)
        function4()

    if(scan_local == "5"):
        print()
        print("*** Returning to the main menu ***")
        time.sleep(2)
        return start

    else:
        print("Error you did not fill in a number from the list. Please try again and check if you only fill in the number of the choice.")
        time.sleep(2)
        print()
        return menu_2()

#local function 1
def port_scanner():
    ip = socket.gethostbyname (socket.gethostname())  #getting ip-address of host
    for port in range(65535):      #check for all available ports
        try:
            serv = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # create a new socket
            serv.bind((ip,port)) # bind socket with address
             
        except:
            print('[OPEN] Port open :',port) #print open port number
            
        serv.close() #close connection
    time.sleep(2)
    print()
    return restart()
    

#local function 2
def system_scanner():
    print("="*20, "System Information", "="*20)
    uname = platform.uname()
    print(f"System: {uname.system}")
    print(f"Node Name: {uname.node}")
    print(f"Release: {uname.release}")
    print(f"Version: {uname.version}")
    print(f"Machine: {uname.machine}")
    print(f"Processor: {uname.processor}")
    print()
    #print(f"Kernel: {uname.kernel}")
    time.sleep(2)
    print()
    return restart()

#local function 3   
def network_info_scanner():
    print("="*20, "Network Information", "="*20)
    # get all network interfaces (virtual and physical)
    if_addrs = psutil.net_if_addrs()
    for interface_name, interface_addresses in if_addrs.items():
        for address in interface_addresses:
            print(f"--- Interface: {interface_name} ---")
            if str(address.family) == 'AddressFamily.AF_INET':
                print(f"  IP Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast IP: {address.broadcast}")
            elif str(address.family) == 'AddressFamily.AF_PACKET':
                print(f"  MAC Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast MAC: {address.broadcast}")
    time.sleep(2)
    print()
    return restart()


#restart
def restart():
    print("")
    print("Do you want to do a different scan?")
    start_again = input("Type yes or no:   ")
    if (start_again == "yes") or (start_again == "y") or (start_again == "YES") or (start_again == "Y"):
        print("*** Returning to the main menu ***")
        print()
        time.sleep(2)
        return start()

    elif (start_again == "no") or (start_again == "n") or (start_again == "NO") or (start_again == "N"):
        print("*** Closing the program ***")
        time.sleep(2)
        sys.exit()

    else:
        print("Error you didn't type yes or no. Please make sure you only use lowercase letters.")
        print()
        time.sleep(2)
        return restart()

start()
