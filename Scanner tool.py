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
    loop_start = True
    while loop_start == True:
        print()
        print("######## WELCOME TO MY SCANNER APPLICATION ########")
        print("*** MAIN MENU ***")
        print("choose 1: for remote scans")
        print("choose 2: for local scans")
        print("choose 3: to exit the application")
        menu_choice = input("What kind of scan do you want to execute? (only type the number of your choice):    ")
        if(menu_choice == "1"):
            loop_start = False
            menu_1()

        if(menu_choice == "2"):
            loop_start = False
            menu_2()

        if(menu_choice == "3"):
            sys.exit()

        else:
            print()
            print("Error! You didn't type one of the numbers listed above, Please try again.")
            loop_start = True
    
#REMOTE scan menu
def menu_1():
    loop_menu1 = True
    while loop_menu1 == True:
        print()
        print("*** REMOTE SCAN MENU ***")
        print("Here is a list with scans you can execute remotely:")
        print("choose 1: scan for mac addresses on your network")
        print("choose 2: website scanner")
        print("choose 3: go back to the main menu")
        scan_remote = input("What remote scan do you want to execute? (only type the number of your choice):    ")
        if(scan_remote == "1"):
            print()
            print("*** MAC ADDRESS SCANNER ***")
            time.sleep(2)
            loop_menu1 = False
            mac_addr_scanner()
    
        if(scan_remote == "2"):
            print()
            print("*** WEBSITE IP SCANNER ***")
            time.sleep(2)
            loop_menu1 = False
            website_scanner()
        
        if(scan_remote == "3"):
            print()
            print("*** Returning to the main menu ***")
            time.sleep(2)
            loop_menu1 = False
            start()

        else:
            print()
            print("Error! You didn't type one of the numbers listed above, Please try again.")
            time.sleep(2)
            loop_menu1 = True

#remote function 1
def mac_addr_scanner():
    loop_mac = True
    while loop_mac == True:
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
        print("IP" + " "*22+"MAC")
    
        for client in clients:
            print("{:16}    {}".format(client['ip'], client['mac']))

        print()
        print("If the IP and or MAC address aren't filled in, the scanner can't find the device linked to the IP address you filled in.")

        time.sleep(2)
        loop_mac = False
        restart()

#Remote function 2
def website_scanner():
    loop_website = True
    while loop_website == True:
        try:
            domain_name = input("Please type the domain name of your target (example.com):    ")
            domain_addres = socket.gethostbyname(domain_name)
            print("IP Address is: " + domain_addres)
            loop_website = False
        except:
            print("We are unable to find the domain name and IP address.")
            print()
            print("---------- We will redirect you to the restart menu to try again ----------")
            loop_website = False

    time.sleep(2)
    restart()

#LOCAL scan menu
def menu_2():
    loop_menu2 = True
    while loop_menu2 == True:
        print()
        print("*** LOCAL SCAN MENU ***")
        print("Here is a list with scans you can execute locally:")
        print("choice 1: port scanner")
        print("choice 2: system information scanner")
        print("choice 3: network information scanner")
        print("choose 4 to go back to the main menu")
        scan_local = input("What scan do you want to execute? (only type the number of your choice):    ")
        if(scan_local == "1"):
            print()
            print("*** PORT SCANNER ***")
            time.sleep(2)
            loop_menu2 = False
            port_scanner()

        if(scan_local == "2"):
            print()
            print("*** SYSTEM INFORMATION SCANNER ***")
            time.sleep(2)
            loop_menu2 = False
            system_scanner()

        if(scan_local == "3"):
            print()
            print("*** NETWORK SCANNER ***")
            time.sleep(2)
            loop_menu2 = False
            network_info_scanner()

        if(scan_local == "4"):
            print()
            print("*** Returning to the main menu ***")
            time.sleep(2)
            loop_menu2 = False
            start()
        

        else:
            print()
            print("Error you did not fill in a number from the list. Please try again and check if you only fill in the number of the choice.")
            time.sleep(2)
            loop_menu2 = True

#local function 1
def port_scanner():
    loop_port = True
    while loop_port == True:
        ip = socket.gethostbyname (socket.gethostname())  #getting ip-address of host
        for port in range(0, 65535):      #check for all available ports
            try:
                serv = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # create a new socket
                serv.bind((ip,port)) # bind socket with address
             
            except:
                print('[OPEN] Port open :',port) #print open port number
            
            serv.close() #close connection
        time.sleep(2)
        print()
        loop_port = False
        restart()
    

#local function 2
def system_scanner():
    loop_system = True
    while loop_system == True:
        print("="*20, "System Information", "="*20)
        uname = platform.uname()
        print(f"System: {uname.system}")
        print(f"Node Name: {uname.node}")
        print(f"Release: {uname.release}")
        print(f"Version: {uname.version}")
        print(f"Machine: {uname.machine}")
        print(f"Processor: {uname.processor}")
        print()
        time.sleep(2)
        print()
        loop_system = False
        restart()

#local function 3   
def network_info_scanner():
    loop_network = True
    while loop_network == True:
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
        loop_network = False
        restart()

#restart
def restart():
    loop_restart = True
    while loop_restart == True:
        print("")
        print("*** RESTART MENU ***")
        print("Do you want to do a different scan? If you select yes, you will be redirected to the main menu.")
        start_again = input("Type yes or no:   ")
        if (start_again == "yes") or (start_again == "y") or (start_again == "YES") or (start_again == "Y"):
            print("*** Returning to the main menu ***")
            print()
            time.sleep(2)
            loop_restart = False
            start()

        elif (start_again == "no") or (start_again == "n") or (start_again == "NO") or (start_again == "N"):
            print()
            print("*** Closing the program ***")
            time.sleep(2)
            loop_restart = False
            sys.exit()

        else:
            print("Error you didn't type yes or no. Please make sure you only use lowercase letters.")
            print()
            time.sleep(2)
            loop_restart = True

start()
