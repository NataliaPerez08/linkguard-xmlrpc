# Deamon del cliente
import logging
from xmlrpc.server import SimpleXMLRPCServer

# Es al mismo tiempo cliente
import xmlrpc.client

# Manejadores de red
from conn_scapy import verificar_conectividad
# Importar configurador de Wireguard
import WG.ConfiguradorWireguardCliente as wg

# Importar os
from os import geteuid
from sys import exit

# Servidor en la nube
dir_servidor="http://172.20.0.10:8000/"

orquestador = xmlrpc.client.ServerProxy(dir_servidor, allow_none=True)

# Servidor local
dir_local = "0.0.0.0"
port_local = 3041
wg_public_key = None
wg_private_key = None
wg_ip = None
wg_port = None
actual_user = None

# Create server
xmlrpc_server = SimpleXMLRPCServer((dir_local,port_local),  logRequests=True)

# Iniciar configurador de Wireguard
wg = wg.ConfiguradorWireguardCliente()

# Iniciar logger
xmlrpc_logger = logging.getLogger('xmlrpc.server')


def register_user(name, email, password):
    """
    Registra un usuario en el servidor
    """
    print(f"Registrando usuario: {name} {email} {password}")
    # Envia lo anterior a logger 
    xmlrpc_logger.info(f"Registrando usuario: {name} {email} {password}")
    is_register = orquestador.register_user(name, email, password)
    if not is_register:
        #print("Error al registrar el usuario! El correo ya esta registrado")
        return False
    #print("Usuario registrado!")
    return True

def identify_me( email, password):
    """
    Identifica un usuario en el servidor
    """
    is_identified = orquestador.identify_user(email, password)
    if not is_identified:
        return False
    return True

def whoami():
    """
    Obtiene el nombre del usuario actual
    """
    return orquestador.whoami()

def create_private_network( nombre):
    """
    Crea una red privada en el servidor
    """
    private_network_id = orquestador.create_private_network(nombre)
    if private_network_id == -1:
        return -1
    return private_network_id

def get_private_networks():
    """
    Recupera las redes privadas del servidor
    """
    priv_net = orquestador.get_private_networks()
    return priv_net

def ver_endpoints(id_red_privada):
    """
    Obtiene los endpoints de una red privada
    """
    endpoints = orquestador.get_endpoints(id_red_privada)
    return endpoints

def conectar_endpoint( id_endpoint, id_red_privada):
    print("Conectando endpoint...")
    # Encontrar la red privada
    private_network = orquestador.get_private_network_by_id(id_red_privada)

    if private_network == -1:
        print("No se encontro la red")
        return

    # Encontrar dispositivo en la red
    endpoint = private_network.get_endpoint_by_id(id_endpoint)

    if endpoint == -1:
        print("No se encontro el Endpoint")
        return

    print(f"Endpoint: {endpoint}")
    print(f"Red privada: {private_network}")
    verificar_conectividad(endpoint.ip_addr, private_network.last_host_assigned)

def conectar_endpoint_directo( ip_endpoint, puerto_endpoint):
    print("Conectando endpoint directo...")
    verificar_conectividad(ip_endpoint)

def obtener_clave_publica_servidor():
    print("Obteniendo clave pública...")
    print(orquestador.get_public_key())

def obtener_configuracion_wireguard_local():
    print("Obteniendo configuracion..")
    conf = wg.get_wg_state()
    print(conf)

def obtener_configuracion_wireguard_servidor():
    print("Preguntar al servidor")
    print(orquestador.get_wireguard_config())

def cerrar_sesion():
    result = orquestador.close_session()
    return result
    


# Inicializar Wireguard en el cliente
def init_wireguard_interface( ip_cliente):
    print("Inicializando Wireguard...")
    wg_private_key, wg_public_key = wg.create_keys()
    print("Clave privada: ", wg_private_key)
    print("Clave pública: ", wg_public_key)

    wg.create_wg_interface(ip_cliente)

    print("Wireguard inicializado!")


# Viene del comando: python3 main.py registrar_como_peer <nombre> <id_red_privada> <ip_cliente> <puerto_cliente>
def configure_as_peer( nombre_endpoint, id_red_privada, ip_cliente, listen_port):
    print("Configurando como peer...")
    endpoint_ip_WG,id_endpoint = orquestador.create_endpoint(id_red_privada, nombre_endpoint)
    if endpoint_ip_WG == -1:
        print("Error al configurar el peer!")
        return -1
    print("IP de Wireguard asignada: ", endpoint_ip_WG)

    # Verificar si la interfaz existe
    if wg.check_interface():
        print("Ya existe la interfaz.")
        return -1
    else:
        print("La interfaz no existe.")
        wg_private_key, wg_public_key = wg.create_wg_interface(ip_cliente)

    # Configurar peer en local
    allowed_ips = orquestador.get_allowed_ips(id_red_privada)
    # Es necesario registrar el orquestador como peer en el cliente
    wg_pk_o = orquestador.get_public_key()
    ip_servidor = orquestador.get_ip()
    port_servidor = orquestador.get_port()
    
    print("Registrando peer en el cliente...")
    result = wg.create_peer(wg_pk_o, allowed_ips, ip_cliente, listen_port)
    print("Peer registrado en el cliente!")

    # Registrar peer en el servidor
    print("Registrando peer en el servidor...,con la llave publica: ", wg_public_key)
    ip_wg_peer = orquestador.create_peer(wg_public_key, allowed_ips, endpoint_ip_WG, listen_port, ip_cliente)
    # Completar endpoint para incluir wg_public_key, allowed_ips, ip_cliente, listen_port
    result = orquestador.complete_endpoint(id_red_privada, id_endpoint, wg_public_key, allowed_ips, ip_cliente, listen_port)
    print(result)

    return ip_wg_peer

def register_peer( public_key, allowed_ips, ip_cliente, listen_port):
    print("Registrando peer en el servidor...")
    endpoint_ip_WG = orquestador.create_peer(public_key, allowed_ips, ip_cliente, listen_port)
    if endpoint_ip_WG == -1:
        print("Error al registrar el peer!")
        return
    print("Peer registrado en el servidor!")
    print("IP de Wireguard asignada: ", endpoint_ip_WG)
    
    print("Registrando peer en el cliente...")
    result = wg.create_peer(public_key, allowed_ips, ip_cliente, listen_port)
    print("Peer registrado en el cliente!")
    return result


# Iniciar el servidor si se ejecuta como superusuario
if __name__ == "__main__":
    print("Iniciando servidor...")
    if geteuid() != 0:
        print("Se necesita permisos de administrador para ejecutar el servidor")
        exit()

    # Guardar las funciones
    xmlrpc_server.register_function(register_user)
    xmlrpc_server.register_function(identify_me)
    xmlrpc_server.register_function(whoami)
    xmlrpc_server.register_function(create_private_network)
    xmlrpc_server.register_function(get_private_networks)
    xmlrpc_server.register_function(ver_endpoints)
    xmlrpc_server.register_function(conectar_endpoint)
    xmlrpc_server.register_function(conectar_endpoint_directo)
    xmlrpc_server.register_function(obtener_clave_publica_servidor)
    xmlrpc_server.register_function(obtener_configuracion_wireguard_local)
    xmlrpc_server.register_function(obtener_configuracion_wireguard_servidor)
    xmlrpc_server.register_function(cerrar_sesion)
    xmlrpc_server.register_function(init_wireguard_interface)
    xmlrpc_server.register_function(configure_as_peer)
    xmlrpc_server.register_function(register_peer)

    print("Servidor iniciado!")
    xmlrpc_server.serve_forever()

