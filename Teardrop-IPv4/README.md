# Teardrop IPv4 – Fragmentation Attack Lab

Laboratório experimental para estudo da fragmentação IPv4 e comportamento de reassembly
em cenários de sobreposição de fragmentos (Teardrop-like).

## Objetivo
Avaliar impacto de fragmentos sobrepostos em:
- Windows XP Pro SP1 (VM)
- Windows 10 Pro (Host)

## Ferramentas
- Scapy (Python)
- Wireshark
- VMware

## Estrutura
- report/ → relatório completo
- scripts/ → scripts Scapy
- images/ → evidências visuais

## Resultados resumidos
Sem crash imediato.
Forte pressão sobre Nonpaged Pool.
Windows 10 mostra maior degradação sob carga prolongada.

## Execução
```bash
python scripts/teardrop_v1.py
python scripts/teardrop_v2.py

