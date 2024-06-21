# SYN сканнер

from scapy.all import IP, ICMP,TCP, sr1
import sys

# Проверка доступен ли хост
def icmp_probe(ip): 
    icmp_packet = IP(dst=ip)/ICMP()
    resp_packet = sr1(icmp_packet, timeout=10)
    return resp_packet != None

# Сканирование по всем портам 
def syn_scan(ip, ports):
    for port in ports:
        syn_packet = IP(dst=ip)/TCP(dport=port, flags="S") # Формирование пакета
        resp_packet = sr1(syn_packet, timeout=10) # Ответ от хоста
        if resp_packet != None:
            if resp_packet.getlayer('TCP').flags & 0x12 !=0: # Проверка флагов SYN, ACK
                print(f"\n{ip}:{port} is open/{resp_packet.sprintf('%TCP.sport%')}\n")
    
if __name__ == "__main__":
    ip = sys.argv[1]
    port = [21, 22, 80, 443] #и другие 2^16 - 4
    try:
        if icmp_probe(ip):
            syn_ack_packet = syn_scan(ip, port)
            syn_ack_packet.show()
        else:
            print("ICMP Probe Failed")
    except AttributeError:
        print("\n===Completed===\n")