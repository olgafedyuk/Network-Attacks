# Proof of Concept (PoC) of the IPv4 Teardrop Attack

This repository contains a practical demonstration of the Teardrop attack, which exploits a vulnerability in the IPv4 fragment reassembly process. The main objective is to learn how to manipulate the datagram header.

## Overview

The attack consists of sending fragments of IP packets with malicious offsets, causing data overlap. Vulnerable systems can instantly suffer from memory exhaustion or critical failure (BSOF/Kernel Panic) while attempting to process these fragments.

### Test Enviroment

* **Attacker:** Python + Scapy.
* **Victim 1:** Windows XP Pro SP1 (VMware via Bridge Mode).
* **Victim 2:** Windows 10 Pro (Host).

## Repository Structure

```text
teardrop-ipv4/
├─ README.md               
├─ report/                 # Detailed documentation
│   └─ Report_Teardrop_IPv4.md
├─ images/                 # Evidences of sistem impact
│   ├─ xp_idle.png
│   ├─ xp_attack.png
│   ├─ win10_idle.png
│   └─ win10_attack.png
└─ scripts/                # PoC in Python
    ├─ teardrop_v1.py      # Script of validation
    └─ teardrop_v2.py      # Autamated script with IP Spoofing

```

## How it works

This technique exploits the **Offset** field of the second packet, setting it to the lowest value at the end of the second packet, forcing the kernel to handle conflicting data.

### Example of Logic (Scapy)

```python
# Fragment 1: Starts at byte 0 with 1408 bytes of payload
p1 = IP(dst=target, flags=1)/UDP(sport=123, dport=80)/("A"*1400)
# Fragment 2: Starts at byte 64 (frag=1), causing massive overlap
p2 = IP(dst=target, frag=1, proto=17)/("B"*1400)
```

## Result and impact

During Wireshark analysis, the acceptance of overlapping fragments (`Reassembled IPv4`) was confirmed. The use of **port 123 (NTP)** was applied to bypass firewalls.

### Performance Comparison

| Sistema | Impacto Observado | Resiliência |
| --- | --- | --- |
| **Windows XP SP1** | Controlled increase in *Non-Paged Pool* (+151 MB). | Stable (Native protection against blocking). |
| **Windows 10 Pro** | RAM usage jumped from 43% to 96%. Cache drastically reduced. | Vulnerable due to resource exhaustion (DoS due to slowness). |
## Conclusion

Even if the system does not suffer an immediate crash (Direct Screen of Death - DSOD), Windows 10 demonstrates vulnerability to resource exhaustion, resulting in slowness and difficulty in restoring memory even after the attack ends. 

---

**Note:** To obtain the complete technical report with evidence and analysis, access the directory [`/report`](https://www.google.com/search?q=./report/Report_Teardrop_IPv4.md).