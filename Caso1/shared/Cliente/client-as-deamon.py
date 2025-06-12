# Deamon del cliente
import logging
from xmlrpc.server import SimpleXMLRPCServer

# Es al mismo tiempo cliente
import xmlrpc.client

# Manejadores de red
from conn_scapy import verificar_conectividad
# Importar configurador de Wireguard
import WG.ConfiguradorWireguardCliente as ConfiguradorWireguardCliente


# Importar os
from os import geteuid
from sys import exit


class ClientAsDeamon:
    """
    Clase que representa al cliente como un deamon
    """
    def __init__(self,dir_servidor, public_ip,port_local=3041):
        self.orquestador = None
        self.wg = None
        # Servidor en la nube
        self.dir_servidor= f"http://{dir_servidor}:8000/"
        self.orquestador = xmlrpc.client.ServerProxy(self.dir_servidor, allow_none=True)
        # Servidor local
        self.dir_local = "0.0.0.0"
        self.port_local = port_local
        self.wg_public_key = None
        self.wg_private_key = None
        self.wg_ip = None
        self.wg_port = None
        self.actual_user = None
        self.public_ip = public_ip
        # Create server
        self.xmlrpc_server = SimpleXMLRPCServer((self.dir_local, self.port_local), logRequests=True)
        # Iniciar configurador de Wireguard
        self.wg = ConfiguradorWireguardCliente.ConfiguradorWireguardCliente()
        # Iniciar logger
        self.xmlrpc_logger = logging.getLogger('xmlrpc.server')


    def start_server(self):
        """
        Inicia el servidor XML-RPC
        """
        print("Iniciando servidor XML-RPC...")
        # Create keys
        self.wg_private_key, self.wg_public_key = self.wg.create_keys()
        self.xmlrpc_server.register_instance(self)
        self.xmlrpc_server.serve_forever()
        print("Servidor XML-RPC iniciado en {}:{}".format(self.dir_local, self.port_local))


    def register_user(self, name, email, password):
        """
        Registra un usuario en el servidor
        """
        print(f"Registrando usuario: {name} {email} {password}")
        # Envia lo anterior a logger 
        self.xmlrpc_logger.info(f"Registrando usuario: {name} {email} {password}")
        is_register = self.orquestador.register_user(name, email, password)
        if not is_register:
            #print("Error al registrar el usuario! El correo ya esta registrado")
            return False
        #print("Usuario registrado!")
        return True

    def identify_me(self, email, password):
        """
        Identifica un usuario en el servidor
        """
        is_identified = self.orquestador.identify_user(email, password)
        if not is_identified:
            return False
        return True

    def whoami(self):
        """
        Obtiene el nombre del usuario actual
        """
        return self.orquestador.whoami()

    def create_private_network(self, nombre):
        """
        Crea una red privada en el servidor
        """
        private_network_id = self.orquestador.create_private_network(nombre)
        if private_network_id == -1:
            return -1
        return private_network_id

    def get_private_networks(self):
        """
        Recupera las redes privadas del servidor
        """
        priv_net = self.orquestador.get_private_networks()
        return priv_net

    def get_endpoints(self, id_red_privada):
        """
        Obtiene los endpoints de una red privada
        """
        endpoints = self.orquestador.get_endpoints(id_red_privada)
        return endpoints

    def connect_endpoint(self, id_endpoint, id_red_privada):
        print("Conectando endpoint...")
        # Encontrar la red privada
        private_network = self.orquestador.get_private_network_by_id(id_red_privada)

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

    def test_connection(self, ip_endpoint, puerto_endpoint):
        print("Conectando endpoint directo...")
        verificar_conectividad(ip_endpoint)

    def close_session(self):
        result = self.orquestador.close_session()
        return result
        


    # Inicializar Wireguard en el cliente
    def init_wireguard_interface(self, ip_cliente):
        print("Inicializando Wireguard...")
        wg_private_key, self.wg_public_key = self.wg.create_keys()
        print("Clave privada: ", wg_private_key)
        print("Clave pública: ", self.wg_public_key)

        self.wg.create_wg_interface(ip_cliente)

        print("Wireguard inicializado!")


    # Viene del comando: python3 main.py registrar_como_peer <nombre> <id_red_privada> <ip_cliente> <puerto_cliente>
    def configure_as_peer(self, nombre_endpoint, id_red_privada, ip_cliente, listen_port):
        print("Configurando como peer...")
        endpoint_ip_WG,id_endpoint = self.orquestador.create_endpoint(id_red_privada, nombre_endpoint)
        if endpoint_ip_WG == -1:
            print("Error al configurar el peer!")
            return -1
        print("IP de Wireguard asignada: ", endpoint_ip_WG)

        # Verificar si la interfaz existe
        if self.wg.check_interface():
            print("Ya existe la interfaz.")
        else:
            print("La interfaz no existe.")
            # Crear la interfaz de Wireguard
            self.init_wireguard_interface(public_ip)

        # Configurar peer en local
        print("Obtener la clave publica del servidor...")
        allowed_ips = self.orquestador.get_allowed_ips(id_red_privada)
        print("Allowed IPs: ", allowed_ips)
        # Es necesario registrar el self.orquestador como peer en el cliente
        wg_o_pk, wg_o_port, wg_o_ip = self.orquestador.get_wireguard_config()
        print("Clave publica del servidor: ")
        print(wg_o_pk)
        print("Puerto del servidor: ", wg_o_port)
        print("IP del servidor: ", wg_o_ip)

        print("Crear el peer en el cliente...")
        result = self.wg.create_peer(wg_o_pk, allowed_ips, wg_o_ip, wg_o_port)
        print("Peer registrado en el cliente!")

        # Registrar peer en el servidor
        print("Registrando peer en el servidor...,con la llave publica: ", self.wg_public_key)
        ip_wg_peer = self.orquestador.create_peer(self.wg_public_key, allowed_ips, endpoint_ip_WG, listen_port, ip_cliente)
        # Completar endpoint para incluir self.wg_public_key, allowed_ips, ip_cliente, listen_port
        result = self.orquestador.complete_endpoint(id_red_privada, id_endpoint, self.wg_public_key, allowed_ips, ip_cliente, listen_port)
        print(result)

        return ip_wg_peer

    def register_peer(self, public_key, allowed_ips, ip_cliente, listen_port):
        print("Registrando peer en el servidor...")
        endpoint_ip_WG = self.orquestador.create_peer(public_key, allowed_ips, ip_cliente, listen_port)
        if endpoint_ip_WG == -1:
            print("Error al registrar el peer!")
            return
        print("Peer registrado en el servidor!")
        print("IP de Wireguard asignada: ", endpoint_ip_WG)
        
        print("Registrando peer en el cliente...")
        result = self.wg.create_peer(public_key, allowed_ips, ip_cliente, listen_port)
        print("Peer registrado en el cliente!")
        return result


# Iniciar el servidor si se ejecuta como superusuario
if __name__ == "__main__":
    if geteuid() != 0:
        print("Se necesita permisos de administrador para ejecutar el servidor")
        exit()
    # Registrar funciones del cliente
    dir_servidor= "localhost"  # Cambiar por la dirección del servidor
    public_ip = "0.0.0.0.0"  # Cambiar por la IP pública del cliente
    client_as_deamon = ClientAsDeamon(dir_servidor, public_ip) 
    # Iniciar el servidor XML-RPC
    client_as_deamon.start_server()
