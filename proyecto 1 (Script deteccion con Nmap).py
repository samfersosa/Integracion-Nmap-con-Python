import nmap
import socket
import sys
import html
from datetime import datetime
from collections import Counter

def obtener_banner(ip, puerto):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, puerto))
        if puerto in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else ""
    except:
        return ""

def analizar_riesgos(host_data):
    """Aplica reglas de negocio para generar observaciones automáticas"""
    observaciones = []
    puertos_abiertos = [p['port'] for p in host_data['ports']]
    
    # Regla: Alta exposición por cantidad
    LIMITE_EXPOSICION = 5
    if len(puertos_abiertos) > LIMITE_EXPOSICION:
        observaciones.append(f"⚠️ <b>ALTA EXPOSICIÓN:</b> Se detectaron {len(puertos_abiertos)} puertos abiertos.")

    # Reglas por puertos específicos
    reglas = {
        22: "🔑 <b>SSH Expuesto:</b> Posible acceso remoto por consola.",
        3389: "🖥️ <b>RDP Accesible:</b> Escritorio remoto detectado (Objetivo crítico).",
        445: "📁 <b>SMB Expuesto:</b> Compartición de archivos activa (Riesgo de Ransomware).",
        21: "📂 <b>FTP Detectado:</b> Protocolo inseguro de transferencia de archivos.",
        23: "📟 <b>Telnet Abierto:</b> ¡Extremo peligro! Tráfico sin cifrar."
    }

    for puerto, mensaje in reglas.items():
        if puerto in puertos_abiertos:
            observaciones.append(mensaje)

    # Regla: Identificar servidor HTTP mediante Banner
    for p in host_data['ports']:
        if "Server:" in p['banner']:
            # Extraer solo la línea del servidor
            for line in p['banner'].split('\n'):
                if "Server:" in line:
                    observaciones.append(f"🌐 <b>Software Web:</b> Detectado {line.strip()}")

    return observaciones

def generar_reporte_pro(resultados, red):
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M")
    total_hosts = len(resultados)
    total_ports = sum(len(h['ports']) for h in resultados)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <style>
            :root {{ --alto: #e74c3c; --medio: #f39c12; --bajo: #27ae60; --oscuro: #2c3e50; }}
            body {{ font-family: 'Segoe UI', sans-serif; background: #f4f7f6; padding: 30px; }}
            .card {{ background: white; border-radius: 12px; padding: 20px; margin-bottom: 25px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); border-left: 8px solid var(--oscuro); }}
            .obs-box {{ background: #fff5f5; border: 1px solid #feb2b2; padding: 15px; border-radius: 8px; margin-top: 15px; }}
            .obs-item {{ margin: 5px 0; font-size: 0.95em; color: #c53030; list-style: none; }}
            .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
            .stat-item {{ background: var(--oscuro); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th {{ text-align: left; background: #f8fafc; padding: 10px; font-size: 0.8em; color: #64748b; }}
            td {{ padding: 12px 10px; border-bottom: 1px solid #f1f5f9; }}
            .badge {{ padding: 4px 8px; border-radius: 6px; font-size: 0.75em; font-weight: bold; color: white; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Dashboard de Seguridad: {red}</h1>
        <div class="stat-grid">
            <div class="stat-item"><h3>Hosts</h3><p>{total_hosts}</p></div>
            <div class="stat-item"><h3>Puertos Total</h3><p>{total_ports}</p></div>
            <div class="stat-item"><h3>Fecha</h3><p>{fecha}</p></div>
        </div>
    """

    for host in resultados:
        obs = analizar_riesgos(host)
        html_content += f"""
        <div class="card">
            <h2 style="margin:0;">🖥️ {host['ip']}</h2>
            <p style="color: #64748b; margin: 5px 0;">Hostname: {host['hostname']}</p>
            
            <table>
                <thead><tr><th>PUERTO</th><th>SERVICIO</th><th>BANNER</th></tr></thead>
                <tbody>"""
        
        for p in host['ports']:
            html_content += f"""
                <tr>
                    <td><b>{p['port']}</b></td>
                    <td>{p['service']} <br> <small style="color:#94a3b8">{html.escape(p['version'])}</small></td>
                    <td><code style="font-size:0.8em;">{html.escape(p['banner'][:100])}</code></td>
                </tr>"""
        
        html_content += "</tbody></table>"

        if obs:
            html_content += '<div class="obs-box"><b>🔍 Hallazgos de Seguridad:</b><ul>'
            for item in obs:
                html_content += f'<li class="obs-item">{item}</li>'
            html_content += '</ul></div>'
            
        html_content += "</div>"

    html_content += "</body></html>"
    with open("reporte_final.html", "w", encoding="utf-8") as f: f.write(html_content)

def escanear_red(red):
    nm = nmap.PortScanner()
    puertos = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
    print(f"[*] Escaneando e identificando riesgos en {red}...")
    
    nm.scan(hosts=red, ports=puertos, arguments='-Pn -n -sV -T4')
    resultados = []
    for host in nm.all_hosts():
        datos_host = {"ip": host, "hostname": nm[host].hostname() or "N/A", "ports": []}
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                datos_host["ports"].append({
                    "port": port, "service": info['name'],
                    "version": f"{info.get('product', '')} {info.get('version', '')}".strip(),
                    "banner": obtener_banner(host, port)
                })
        resultados.append(datos_host)
    
    generar_reporte_pro(resultados, red)
    print(f"[✔] Reporte generado: reporte_final.html")

if __name__ == "__main__":
    escanear_red(sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org")