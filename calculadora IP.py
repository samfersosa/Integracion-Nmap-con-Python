import ipaddress

def analizar_red(rango_red):
    try:
        # Creamos un objeto de red
       
        red = ipaddress.ip_network(rango_red, strict=False)

        print(f"--- Análisis de la red: {rango_red} ---")
        
        # 1. Dirección de Red
        print(f"Network Address:  {red.network_address}")

        # 2. Dirección de Broadcast
        print(f"Broadcast Address: {red.broadcast_address}")

        # 3. Número de hosts (incluyendo red y broadcast)
        print(f"Total de IPs:      {red.num_addresses}")
        
        # Número de hosts usables (para dispositivos)
        # Se restan 2 (red y broadcast)
        hosts_usables = list(red.hosts())
        print(f"Hosts usables:     {len(hosts_usables)}")

        # 4. Primeras y últimas IPs usables
        if len(hosts_usables) > 0:
            print(f"Primera IP usable: {hosts_usables[0]}")
            print(f"Última IP usable:  {hosts_usables[-1]}")
        
    except ValueError as e:
        print(f"Error: El rango {rango_red} no es válido. {e}")

# Ejecución
rango = "192.168.1.0/24" # Ip generica
analizar_red(rango)