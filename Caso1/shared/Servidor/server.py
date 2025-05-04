
## Server-Orquestrador
from xmlrpc.server import SimpleXMLRPCServer

# Mis clases
from usuario import Usuario
import PrivateNetwork as rp
import WG.configGeneratorServer as wg

import os
import sys

dir = "0.0.0.0"
port = 8000
xmlrpc_server = SimpleXMLRPCServer((dir, port))
# Usuario actual
usuario = None

# Lista de usuarios [id: Usuario]
usuarios = dict()

# Llave pública de Wireguard del orquestador
wg_private_key = None
wg_public_key = None

# La ip del servidor Wireguard
wg_ip = ""
# El puerto del servidor Wireguard
wg_port = 0
# La ip publica del servidor Wireguard
public_ip = ""


def init_wireguard(wg_ip_p, wg_port_p, public_ip_p):
    """
    Crea la interfaz
    """
    wg_ip = wg_ip_p
    wg_port = wg_port_p
    public_ip = public_ip_p
    # Crear las claves pública y privada
    private_key, public_key = wg.create_keys()
    wg.create_wg_interface(wg_ip, public_key, private_key)


def register_user(self, name, email, password):
    """
    Registra un usuario en el servidor
    """
    print("Registrando usuario...")
    if email in usuarios:
        return False

    usuario = Usuario(name, email, password)
    usuarios[email] = usuario
    print("Usuario registrado",usuario.name,"!")
    print(usuarios)
    return True

def identify_user(self, email, password):
    """
    Identifica a un usuario en el servidor
    """
    print("Buscando usuario...")

    try:
        usuario = usuarios[email]
        if usuario is not None and usuario.password == password:
            usuario = usuario
            print("Usuario identificado!")
            return True
    except:
        return False
    return  False

def whoami(self):
    """
    Recupera el usuario actual
    """
    if usuario is None:
        return "No hay usuario"
    else:
        return usuario.name

def close_session(self):
    """
    Cierra la sesión del usuario
    """
    usuario = None
    return True

def create_private_network(self,net_name) -> int:
    """
    Crea una red privada
    """
    if usuario is None:
        return -1
    else:
        # Crear la red privada
        counter = usuario.private_network_counter
        red = rp.PrivateNetwork(counter, net_name,'10.0.0.0', 28)
        usuario.private_networks[str(red.id)] = red
        usuario.private_network_counter += 1
        return red.id

def get_private_networks(self)->list[str]:
    """
    Recupera las redes privadas del usuario
    """
    if usuario is None:
        return ["No hay usuario"]
    else:
        user_private_networks = usuario.get_private_networks()
        return [str(red) for red in user_private_networks.values()]

def get_private_network_by_id(self, net_id):
    """
    Recupera una red privada por su id
    """
    if usuario is None:
        return -1
    else:
        private_network = usuario.get_private_network_by_id(net_id)
        print("Private network:",private_network, type(private_network))
        if private_network is None:
            return -1
        return private_network

def create_endpoint(self, private_network_id, endpoint_name):
    """
    Crea un endpoint en una red privada
    """
    if usuario is None:
        return -1
    else:
        print("Creando endpoint...")
        private_network = get_private_network_by_id(private_network_id)
        if type(private_network) is not rp.PrivateNetwork:
            return -1

        endpoint = private_network.create_endpoint(endpoint_name)
        print("Endpoint creado! ",endpoint.get_id())
        return endpoint.get_wireguard_ip(), endpoint.get_id()
    
def complete_endpoint(self,id_red_privada, id_endpoint, wg_public_key, allowed_ips, ip_cliente, listen_port):
    """
    Completa la configuración del endpoint
    """
    print("Completando endpoint...")
    private_network = get_private_network_by_id(id_red_privada)
    if type(private_network) is not rp.PrivateNetwork:
        return -1

    endpoint = private_network.get_endpoint_by_id(id_endpoint)
    if type(endpoint) is not rp.Endpoint:
        return -1

    endpoint.set_wireguard_public_key(wg_public_key)
    endpoint.set_allowed_ips(allowed_ips)
    endpoint.set_listen_port(listen_port)
    endpoint.set_wireguard_ip(ip_cliente)
    return True

def get_endpoints(self, private_network_id):
    """
    Recupera los endpoints de una red privada
    """
    if usuario is None:
        return []
    else:
        private_network = get_private_network_by_id(private_network_id)
        return private_network.endpoints

def get_public_key(self):
    """
    Recupera la llave pública de Wireguard del orquestrador
    """
    return wg_public_key

def get_allowed_ips(self, private_network_id):
    """
    Recupera las IPs permitidas de una red privada
    """
    private_network = get_private_network_by_id(private_network_id)
    return private_network.get_available_hosts()


def get_wireguard_config(self):
    print("Configurando Wireguard...")
    print("Obteniendo la llave pública del servidor...")
    print("Llave pública del servidor: ", wg_public_key)
    print("Puerto Wireguard del servidor: ", wg_port)
    return wg_public_key, wg_port, public_ip

def create_peer(self, public_key, allowed_ips, endpoint_ip_WG, listen_port, ip_cliente):
    print("Crear peer en el servidor")
    print(public_key, allowed_ips, endpoint_ip_WG, listen_port, ip_cliente)

    wg.create_peer(public_key, allowed_ips, ip_cliente, listen_port)
    print("IP de Wireguard asignada: ", endpoint_ip_WG)
    return endpoint_ip_WG

def connect_peers(ip_i, ip_j, port_i, port_j):
    # Set Up IP Tables Rules on Host Z To allow traffic to be forwarded between host A and host B, you need to set up appropriate iptables rules on host Z.
    wg.setup_iptables(ip_i, ip_j)
    # Save the IP Tables Rules
    wg.save_iptables()

xmlrpc_server.register_function(register_user)
xmlrpc_server.register_function(identify_user)
xmlrpc_server.register_function(whoami)
xmlrpc_server.register_function(close_session)
xmlrpc_server.register_function(create_private_network)
xmlrpc_server.register_function(get_private_networks)
xmlrpc_server.register_function(get_private_network_by_id)
xmlrpc_server.register_function(create_endpoint)
xmlrpc_server.register_function(complete_endpoint)
xmlrpc_server.register_function(get_endpoints)
xmlrpc_server.register_function(get_public_key)
xmlrpc_server.register_function(get_allowed_ips)
xmlrpc_server.register_function(get_wireguard_config)
xmlrpc_server.register_function(create_peer)
xmlrpc_server.register_function(connect_peers)


# Verifica que se ejecute como root
if os.geteuid() != 0:
    print("Necesitas ejecutar este script como root!")
    sys.exit(1)

# La ip del servidor Wireguard
wg_ip = "10.0.0.1"
# El puerto del servidor Wireguard
wg_port = 51820
# La ip publica del servidor Wireguard
public_ip = "172.20.0.11"

init_wireguard(wg_ip, wg_port, public_ip)
print("Listening on port ",port)
xmlrpc_server.serve_forever()

