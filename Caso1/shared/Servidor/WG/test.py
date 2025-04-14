import configGeneratorServer


print("Configuración del servidor WireGuard")
# Crear una interfaz wg
private_key, public_key = configGeneratorServer.create_keys()

print("Llave privada:", private_key)
print("Llave pública:", public_key)

# Crear una interfaz wg
create_interface = configGeneratorServer.create_wg_interface(ip_wg="10.0.0.2", public_key=public_key, private_key=private_key, peer_public_key=None, peer_allowed_ips=None, peer_endpoint_ip=None, peer_listen_port=None)
print("Interfaz wg creada:", create_interface)


# Crear un peer
peer_public_key, peer_private_key = configGeneratorServer.create_keys()
print("Llave privada peer:", peer_private_key)
print("Llave pública peer:", peer_public_key)

peer_allowed_ip = ["10.0.0.1/24"]
endpoint_ip = "192.168.0.1"
listen_port = 51820
print("IP permitidas peer:", peer_allowed_ip)
# Crear un peer
#configGeneratorServer.create_peer(peer_public_key, peer_allowed_ip, endpoint_ip, listen_port)
#print("Peer creado:", peer_public_key)

print("Configuración del servidor WireGuard terminada")

import ConfiguradorWireguardCliente

print("Configuración del cliente WireGuard")

# Crear una interfaz wg
config_generator_client = ConfiguradorWireguardCliente.ConfiguradorWireguardCliente()
private_key, public_key = config_generator_client.create_keys()
print("Llave privada:", private_key)  
print("Llave pública:", public_key)

# Crear una interfaz wg
config_generator_client.create_wg_interface(ip_wg="10.0.0.3")
print("Interfaz wg creada:", config_generator_client.check_interface())


# Crear un peer
peer_allowed_ip = ["10.0.0.1/24"]
endpoint_ip = "192.168.0.1"
listen_port = 51820
print("IP permitidas peer:", peer_allowed_ip)
# Crear un peer
config_generator_client.create_peer(public_key, peer_allowed_ip, endpoint_ip, listen_port)
print("Peer creado:", public_key)

print("Configuración del cliente WireGuard terminada")
