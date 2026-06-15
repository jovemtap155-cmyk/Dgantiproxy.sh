# Scanner.sh
#!/bin/bash
# Scanner de Segurança - Criado para Jovemtap155-cmyk

# Criando o script Python internamente
cat << 'EOF' > scanner_engine.py
import subprocess
import time
import re
from datetime import datetime

SUSPICIOUS_UIDS = ["10292", "10306", "10311"]
WELL_KNOWN_PORTS = ["80", "443", "22", "21", "25", "53", "8080", "3306", "5432"]

def get_data():
    ps = subprocess.run("ps -A -o USER,PID,PPID,NAME,ARGS", shell=True, capture_output=True, text=True).stdout
    ss = subprocess.run("ss -tna | grep ESTAB", shell=True, capture_output=True, text=True).stdout
    return ps.strip().split("\n"), ss.strip().split("\n")

print("\033[1;32m[+] SCANNER EM TEMPO REAL INICIADO\033[0m")
try:
    while True:
        timestamp = datetime.now().strftime("%H:%M:%S")
        procs, conns = get_data()
        
        print(f"\n\033[1;34m--- MONITORAMENTO {timestamp} ---\033[0m")
        
        # Monitorar Processos
        for p in procs:
            if any(uid in p for uid in SUSPICIOUS_UIDS):
                print(f"\033[1;31m[ALERTA PROCESSO]\033[0m {p}")
        
        # Monitorar Conexões
        for c in conns:
            if not c or "Local Address" in c: continue
            match = re.search(r"ESTAB\s+\d+\s+\d+\s+((?:\[[0-9a-fA-F:.]+\]|[0-9.]+)):(\d+)\s+((?:\[[0-9a-fA-F:.]+\]|[0-9.]+)):(\d+)", c)
            if match:
                _, _, r_addr, r_port = match.groups()
                if r_port not in WELL_KNOWN_PORTS and not any(x in r_addr for x in ["127.0.0.1", "::1", "192.168.", "10."]):
                    print(f"\033[1;33m[ALERTA TCP]\033[0m Suspeito: {c}")
        
        time.sleep(5)
except KeyboardInterrupt:
    print("\n\033[1;32m[!] Scanner encerrado.\033[0m")
EOF

# Executa o motor do scanner
python3 scanner_engine.py

