import ConfiguradorWireguardCliente

print("Configuración del cliente WireGuard")

# Crear una interfaz wg

private_key, public_key = ConfiguradorWireguardCliente.create_keys()
print("Llave privada:", private_key)  
print("Llave pública:", public_key)

# Crear una interfaz wg
ConfiguradorWireguardCliente.create_wg_interface(public_key=public_key, private_key=private_key, ip_wg="10.0.0.2")
print("Interfaz wg creada:", ConfiguradorWireguardCliente.check_interface())


# Crear un peer
peer_allowed_ip = ["10.0.0.0/24"]
endpoint_ip = "192.168.0.1"
listen_port = 51820
print("IP permitidas peer:", peer_allowed_ip)
# Crear un peer
ConfiguradorWireguardCliente.create_peer(public_key, peer_allowed_ip, endpoint_ip, listen_port)
print("Peer creado:", public_key)

print("Configuración del cliente WireGuard terminada")
