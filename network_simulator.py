import time
import random
import requests
from icmplib import ping


BACKEND_NETWORK_URL = "http://localhost:3000/api/v1/network-data" # Exemplu de URL

# Lista de servere publice pe care le vom ping-ui
PING_TARGETS = [
    '8.8.8.8',     # Google DNS
    '1.1.1.1',     # Cloudflare DNS
    '9.9.9.9',     # Quad9 DNS
    '208.67.222.222' # OpenDNS
]

LOOP_DELAY_SECONDS = 5  # Trimite date o dată la 5 secunde
ANOMALY_CHANCE = 0.1   # 10% șansă la fiecare ping de a simula un atac DDoS

def simulate_network_traffic():
    """
    Rulează o buclă infinită care simulează traficul de rețea și trimite 
    datele către Backend (Rolul 2).
    """
    print("=====================================================")
    print("Simulatorul de Rețea a pornit.")
    print(f"Trimite date la: {BACKEND_NETWORK_URL}")
    print("=====================================================")

    while True:
        try:
            # 1. Alege o țintă aleatorie
            target_ip = random.choice(PING_TARGETS)
            
            # 2. Trimite un singur ping (timeout de 2 secunde)
            host = ping(target_ip, count=1, interval=0.2, timeout=2)
            
            is_anomaly = False
            
            if not host.is_alive:
                print(f"AVERTISMENT: Ținta {target_ip} nu răspunde.")
                latency_ms = 9999 # Timp maxim pentru a semnala o problemă
                is_anomaly = True
            else:
                latency_ms = host.avg_rtt
            
            # 3. Simulează anomalia (DDoS)
            # 10% șansă să se activeze
            if not is_anomaly and random.random() < ANOMALY_CHANCE:
                is_anomaly = True
                original_latency = latency_ms
                # Crește latența de 5-10 ori pentru a simula un atac
                latency_ms = original_latency * random.randint(5, 10)
                print(f"*** ATAC DDoS SIMULAT: Latență crescută la {latency_ms:.2f}ms pentru {target_ip} ***")

            # 4. Pregătește pachetul de date (payload)
            payload = {
                "target_ip": target_ip,
                "latency_ms": round(latency_ms, 2),
                "is_anomaly": is_anomaly
            }
            
            # 5. Trimite datele la Backend (Rolul 2)
            try:
                requests.post(BACKEND_NETWORK_URL, json=payload, timeout=3)
                if not is_anomaly:
                    print(f"Date normale trimise: {target_ip} @ {latency_ms:.2f}ms")
            except requests.exceptions.RequestException as e:
                print(f"EROARE: Nu s-a putut conecta la Backend (Rol 2): {e}")

            # 6. Așteaptă înainte de următorul ciclu
            time.sleep(LOOP_DELAY_SECONDS)

        except Exception as e:
            # Prinde orice altă eroare (ex: fără internet) și continuă bucla
            print(f"EROARE în bucla principală: {e}")
            time.sleep(LOOP_DELAY_SECONDS)

if __name__ == "__main__":
    simulate_network_traffic()
