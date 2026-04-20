import nmap
import socket
import sys
import html
import json
from datetime import datetime

def obtener_banner(ip, puerto):
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

def generar_html(resultados, red):
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Reporte de Escaneo - {red}</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f7f9; color: #333; margin: 20px; }}
            .container {{ max-width: 1000px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .summary {{ background: #e8f4fd; padding: 15px; border-left: 5px solid #3498db; margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #3498db; color: white; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .banner-code {{ background: #272822; color: #f8f8f2; padding: 5px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; word-break: break-all; }}
            .status-open {{ color: #27ae60; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Reporte de Auditoría de Red</h1>
            <div class="summary">
                <p><strong>Red Escaneada:</strong> {red}</p>
                <p><strong>Fecha de Ejecución:</strong> {fecha}</p>
                <p><strong>Hosts Detectados:</strong> {len(resultados)}</p>
            </div>
    """

    for host in resultados:
        html_content += f"<h2>Host: {host['ip']} ({host['hostname']})</h2>"
        html_content += """
        <table>
            <thead>
                <tr>
                    <th>Puerto</th>
                    <th>Servicio</th>
                    <th>Versión Detectada</th>
                    <th>Banner Capturado</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for p in host['ports']:
            # Escape de HTML para seguridad
            banner_escaneado = html.escape(p['banner'])
            version_escaneada = html.escape(p['version'])
            
            html_content += f"""
                <tr>
                    <td><strong>{p['port']}</strong></td>
                    <td>{p['service']}</td>
                    <td>{version_escaneada}</td>
                    <td><div class="banner-code">{banner_escaneado}</div></td>
                </tr>
            """
        
        if not host['ports']:
            html_content += "<tr><td colspan='4'>No se detectaron puertos abiertos en los rangos comunes.</td></tr>"
            
        html_content += "</tbody></table>"
        html_content += f"<p><strong>Observaciones:</strong> El host responde a peticiones, pero puede tener firewalls activos bloqueando banners específicos.</p>"

    html_content += """
        </div>
    </body>
    </html>
    """
    
    with open("reporte_escaneo.html", "w", encoding="utf-8") as f:
        f.write(html_content)

def escanear_red(red, puertos="21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"):
    nm = nmap.PortScanner()
    print(f"[+] Iniciando escaneo en {red}...")
    
    try:
        nm.scan(hosts=red, ports=puertos, arguments='-Pn -n -sV -T4')
    except Exception as e:
        print(f"[-] Error: {e}")
        return

    resultados = []
    for host in nm.all_hosts():
        datos_host = {
            "ip": host,
            "hostname": nm[host].hostname() or "Desconocido",
            "ports": []
        }
        
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                banner = obtener_banner(host, port)
                
                datos_host["ports"].append({
                    "port": port,
                    "service": info['name'],
                    "version": f"{info.get('product', '')} {info.get('version', '')}".strip() or "N/A",
                    "banner": banner
                })
        resultados.append(datos_host)
    
    generar_html(resultados, red)
    print("[!] Reporte 'reporte_escaneo.html' generado con éxito.")

if __name__ == "__main__":
    target = "scanme.nmap.org" # Cambia esto por tu red o IP
    if len(sys.argv) > 1:
        target = sys.argv[1]
    escanear_red(target)