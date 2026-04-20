# Integracion-Nmap-con-Python
Herramienta en Python para auditoría de red. Automatiza el descubrimiento de hosts y escaneo de puertos con Nmap, integrando captura de banners vía sockets. Incluye un motor de reglas para detectar riesgos (RDP, SMB, SSH) y genera un dashboard profesional en HTML con métricas de criticidad y hallazgos técnicos.
# 🛡️ Network Security Auditor

Una herramienta integral de reconocimiento de red desarrollada en **Python**. Este script automatiza el descubrimiento de hosts, el escaneo de servicios y el análisis de vulnerabilidades básicas, generando un reporte visual interactivo en HTML.

## 🚀 Características
* **Escaneo Inteligente:** Utiliza `Nmap` para identificar hosts vivos y puertos abiertos.
* **Banner Grabbing Híbrido:** Combina datos de Nmap con conexiones directas de `sockets` para extraer información real de los servicios.
* **Motor de Reglas:** Identifica automáticamente riesgos comunes (RDP expuesto, protocolos sin cifrar, etc.).
* **Reporte HTML Pro:** Dashboard moderno con tarjetas por host, indicadores de criticidad y resumen estadístico.
* **Seguro:** Implementa escape de caracteres para manejar datos de red de forma segura en el navegador.

## 🛠️ Requisitos Técnicos
Antes de ejecutar el script, asegúrate de tener instalado:

1.  **Nmap:** Descárgalo en [nmap.org](https://nmap.org/download.html).
2.  **Librerías de Python:**
    ```bash
    pip install python-nmap
    ```

## 📦 Estructura del Proyecto
```text
├── proyecto 1 (Script deteccion con Nmap).py  # Motor principal e integrado
├── Banner_grabber.py                          # Herramienta manual de sockets
├── calculadora IP.py                          # Utilidad para segmentos de red
├── auditoria_final.html                       # Reporte visual generado
└── README.md                                  # Documentación del proyecto
```
## 💻 Uso
Para escanear una red completa (se recomienda ejecutar con privilegios de administrador para la detección de versiones):
python "proyecto 1 (Script deteccion con Nmap).py" 192.168.1.0/24

## 📊 Resultados
Al finalizar, el script genera automáticamente un archivo llamado auditoria_final.html. Este incluye:

Dashboard: Resumen de hosts activos y servicios encontrados.

Análisis de Riesgos: Listado de hallazgos basados en la exposición de puertos críticos.

Banners: Información técnica recuperada directamente de los servicios.

## ⚖️ Aviso Legal
Este proyecto fue creado con fines educativos y de auditoría ética. El uso de esta herramienta contra redes sin autorización previa es responsabilidad exclusiva del usuario. El autor no se hace responsable por el uso indebido de este software.
