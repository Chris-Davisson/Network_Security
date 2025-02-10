'''
Christopher Davisson
Network Security
Lab5
'''

import sys
import random
from time import sleep
import scapy.all as scapy

##Test Functions--------------------------------------------------------------------------


'''
The concept with testing for windows is 
'''
def test_Windows(target_ip: str):
    itterations: int = 3

    legit_IPID = []
    for i in range(itterations):
        response = send_SYN(target_ip)
        if response and IP in response:
            legit_IPID.append(response[IP].id)
        sleep(0.5)

def test_Ubuntu(target_ip: str):
    print()

def test_OpenBSD(target_ip: str):
    print()

def test_FreeBSD(target_ip: str):
    print()

def test_NetBSD(target_ip: str):
    print()

##Helper Functions-----------------------------------------------------------------------

def send_SYN(target_ip: str , spoof: int = None , target_port: int = 80 , testing: bool = False) -> str:
    try:
        if spoof: 
            ip_layer = scapy.IP(src=spoof, dst=target_ip)
        else:
            ip_layer = scapy.IP(dst=target_ip)

        tcp_layer = scapy.TCP(
            sport = random.randint(1024, 65535),
            dport = target_port,
            flags="S",
            seq=random.randint(0 , 2**32-1)
        )

        packet = ip_layer / tcp_layer

        if testing:
            print("here")
            for i in range(0 , 10):
                res = scapy.sr1(packet, timeout=2 , verbose=0)
                print(res)
                return ""
        else:
            res = scapy.sr1(packet, timeout=2 , verbose=0)
        return res
    except Exception as e:
        print(f"Error {e}")
        return None
        

def send_ICMP(target_ip, spoof: int = None, target_port: int = 80 , testing: bool = False):
    try:
        pkt = scapy.IP(dest=target_ip)/scapy.ICMP()
        return scapy.sr1(pkt, timeout=2, verbose=0)
    except Exception as e:
        print(f"Error {e}")
        return None


def check_incremental():
    print()

def display_IPID_SYN(target_ip):
    x: int = 3
    for i in range(x):
        res = send_SYN(target_ip , testing= True)

def display_IPID_ICMP(target_ip):
    x: int = 3
    for i in range(x):
        res = send_ICMP(target_it , testing = True)

def guess_OS(ip_address: str) -> str:
    return "Windows"


def main() -> None:
    if len(sys.argv) == 2:
        print("Testing Operating Systems...\n")
        OS: str = guess_OS(sys.argv[1])
        print(f"OS:\t{OS}")

    elif len(sys.argv) == 3:
        if(sys.argv[2].tolower() == "syn"):
            print("Testing IPID with SYN packets")
            display_IPID_SYN(sys.argv[1])
        else:
            print("Tesing IPID with ICMP packets")

    else:
        print("The program expects an IP address")

        

if __name__ == "__main__":
    main()


'''
Expected behaviours:
Windows:    Counts sequentaly per destination
Ubuntu:     Global sequentaly


ToDo
Send_SYN
Send_SYN_Spoof


'''