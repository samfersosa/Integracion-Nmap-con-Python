import nmap
import socket
import json
import sys

def obtener_banner(ip, puerto):
    """ Función de socket para capturar el banner real """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, puerto))
        if puerto in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else "Sin respuesta de banner"
    except:
        return "No disponible"

def escanear_red(red, puertos="21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"):
    nm = nmap.PortScanner()
    
    print(f"[+] Escaneando: {red}")
    # Mantenemos tus argumentos originales y el -sV
    argumentos = '-Pn -n -sV -T4'
    
    try:
        nm.scan(hosts=red, ports=puertos, arguments=argumentos)
    except Exception as e:
        print(f"[-] Error al ejecutar Nmap: {e}")
        return

    resultados_totales = []

    for host in nm.all_hosts():
        # Estructura de host como pediste
        datos_host = {
            "ip": host,
            "hostname": nm[host].hostname() if nm[host].hostname() else "unknown",
            "ports": []
        }
        
        if nm[host].all_protocols():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    info_p = nm[host][proto][port]
                    
                    # Capturamos el banner usando la función de socket
                    banner_real = obtener_banner(host, port)
                    
                    # Armamos el objeto del puerto
                    puerto_data = {
                        "port": port,
                        "service": info_p['name'],
                        "version": f"{info_p.get('product', '')} {info_p.get('version', '')}".strip() or "Desconocida",
                        "banner": banner_real
                    }
                    datos_host["ports"].append(puerto_data)
        
        resultados_totales.append(datos_host)
    
    # Al final, mostramos y guardamos el JSON
    print(json.dumps(resultados_totales, indent=2))
    
    with open("escaneo.json", "w") as f:
        json.dump(resultados_totales, f, indent=2)
        print("\n[!] Resultados guardados en 'escaneo.json'")

if __name__ == "__main__":
    target = "scanme.nmap.org" 
    if len(sys.argv) > 1:
        target = sys.argv[1]
    
    escanear_red(target)