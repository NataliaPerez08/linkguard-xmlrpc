from WireGuardConfigurator import WireGuardConfigurator
import time

# Crear configurador
wg = WireGuardConfigurator(interface_name="wg0", listen_port=51820)

# Primero limpiar cualquier interfaz existente
wg.clear_interface()
time.sleep(1)  # Pequeña pausa para asegurar que la interfaz se eliminó

# Generar claves
private, public = wg.create_keys()

# Generar peer keys
peer_private, peer_public, preshared_key = wg.generate_peer_keys()
print(f"Peer Public Key: {peer_public}")  # Para usar en el peer_config

# Crear interfaz con un peer
peer_config = {
    'public_key': peer_public,  # Usar la clave generada
    'allowed_ips': ['10.0.0.2/32'],
    'endpoint_ip': '192.168.1.100',
    'endpoint_port': 51820
}

# Crear la interfaz
wg.create_interface(ip_wg='10.0.0.1/24', peer_config=peer_config)
time.sleep(1)  # Pequeña pausa para que la interfaz se estabilice

# Configurar firewall
wg.configure_firewall(local_ips=['192.168.1.0/24'])
wg.save_firewall_rules()

# Controlar interfaz
wg.interface_down()  # Bajar interfaz
time.sleep(1)
wg.interface_up()    # Subir interfaz
time.sleep(1)

# Ver estado
print(f"Interface status: {wg.get_interface_status()}")  # "up" o "down"

# Get current IP - ahora con más tiempo para estabilizarse
current_ip = wg.get_interface_ip()
print(f"Current IP: {current_ip}")  # Debería mostrar "10.0.0.1/24"

# Change IP address
wg.change_interface_ip("10.0.0.2/24")
time.sleep(1)

# Verify change
new_ip = wg.get_interface_ip()
print(f"New IP: {new_ip}")  # Debería mostrar "10.0.0.2/24"


wg.change_interface_ip("10.0.0.1/24")
time.sleep(1)

# Limpiar todo
#wg.clear_interface()