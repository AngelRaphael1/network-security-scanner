import socket
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from datetime import datetime

# Lock para evitar conflitos entre threads
lock = Lock()

# Lista para armazenar os resultados
results = []

# Função responsável por escanear uma porta
def scan_port(ip, port):

    try:
        # Cria socket TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            # Timeout da conexão
            sock.settimeout(1)

            # Testa conexão
            result = sock.connect_ex((ip, port))

            # Se a porta estiver aberta
            if result == 0:

                # Tenta identificar o serviço da porta
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"

                print(f"[OPEN] Porta {port} | Serviço: {service}")

                # Estrutura do resultado
                port_info = {
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "status": "open",
                    "timestamp": str(datetime.now())
                }

                # Evita problemas entre threads
                with lock:
                    results.append(port_info)

    except Exception as e:
        print(f"Erro na porta {port}: {e}")

# Salva os resultados em JSON
def save_results():

    with open("scan_results.json", "w") as file:
        json.dump(results, file, indent=4)

# Função principal
def main():

    print("=" * 40)
    print(" NETWORK SECURITY SCANNER ")
    print("=" * 40)

    # Entrada do IP alvo
    target = input("Digite o IP alvo: ")

    # Lista de portas importantes
    ports = [
        21, 22, 23, 25,
        53, 80, 110, 135,
        137, 139, 143, 443,
        445, 3306, 3389,
        5432, 8080
    ]

    # Horário inicial
    start_time = datetime.now()

    print(f"\n[!] Iniciando scan em {target}")
    print(f"[!] Horário: {start_time.strftime('%H:%M:%S')}\n")

    # Multi-threading
    with ThreadPoolExecutor(max_workers=100) as executor:

        for port in ports:
            executor.submit(scan_port, target, port)

    # Salva relatório
    save_results()

    # Horário final
    end_time = datetime.now()

    # Tempo total
    duration = end_time - start_time

    print("\n" + "=" * 40)
    print(" SCAN FINALIZADO ")
    print("=" * 40)

    print(f"Duração total: {duration}")
    print("Resultados salvos em 'scan_results.json'")

# Execução principal
if __name__ == "__main__":
    main()
