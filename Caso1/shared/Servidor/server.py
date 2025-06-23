## Server-Orquestrador
from xmlrpc.server import SimpleXMLRPCServer

# Mis clases
from usuario import Usuario
import PrivateNetwork as rp
from WG.configGeneratorServer import WireGuardConfigurator

import os
import sys

class Servidor:
    def __init__(self):
        self.dir = "0.0.0.0"
        self.port = 8000
        self.xmlrpc_server = SimpleXMLRPCServer((self.dir, self.port))
        self.xmlrpc_server.register_instance(self)

        # Usuario actual
        self.usuario = None

        # Lista de usuarios [id: Usuario]
        self.usuarios = dict()
        # Llave pública de Wireguard del orquestador
        self.wg_private_key = None
        self.wg_public_key = None
        # La ip del servidor Wireguard
        self.wg_ip = "10.0.0.1"
        # El puerto del servidor Wireguard
        self.wg_port = 51820
        # La ip publica del servidor Wireguard
        self.public_ip = "172.20.0.11"

        self.wg =  WireGuardConfigurator()
    def iniciar(self):
        """
        Inicia el servidor
        """
        self.xmlrpc_server.serve_forever()

    def register_user(self, name, email, password):
        """
        Registra un usuario en el servidor
        """
        print("Registrando usuario...")
        if email in self.usuarios:
            return False

        self.usuario = Usuario(name, email, password)
        self.usuarios[email] = self.usuario
        print("Usuario registrado",self.usuario.name,"!")
        print(self.usuarios)
        return True

    def identify_user(self, email, password):
        """
        Identifica a un usuario en el servidor
        """
        print("Buscando usuario...")

        usuario = self.usuarios[email]
        if usuario is not None and usuario.password == password:
            self.usuario = usuario
            print("Usuario identificado!")
            return True

        return  False

    def whoami(self):
        """
        Recupera el usuario actual
        """
        if self.usuario is None:
            return "No hay usuario"
        else:
            return self.usuario.name

    def close_session(self):
        """
        Cierra la sesión del usuario
        """
        self.usuario = None
        return True

    def create_private_network(self,net_name) -> int:
        """
        Crea una red privada
        """
        if self.usuario is None:
            return -1
        else:
            # Crear la red privada
            counter = self.usuario.private_network_counter
            red = rp.PrivateNetwork(counter, net_name,'10.0.0.0', 28)
            self.usuario.private_networks[str(red.id)] = red
            self.usuario.private_network_counter += 1
            return red.id

    def get_private_networks(self)->list[str]:
        """
        Recupera las redes privadas del usuario
        """
        if self.usuario is None:
            return ["No hay usuario"]
        else:
            user_private_networks = self.usuario.get_private_networks()
            return [str(red) for red in user_private_networks.values()]

    def get_private_network_by_id(self, net_id)-> rp.PrivateNetwork:
        """
        Recupera una red privada por su id
        """
        if self.usuario is None:
            return -1
        else:
            private_network = self.usuario.get_private_network_by_id(net_id)
            print("Private network:",private_network, type(private_network))
            if private_network is None:
                return -1
            return private_network

    def create_endpoint(self, private_network_id, endpoint_name):
        """
        Crea un endpoint en una red privada
        """
        if self.usuario is None:
            return -1
        else:
            print("Creando endpoint...")
            private_network = self.get_private_network_by_id(private_network_id)
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
        private_network = self.get_private_network_by_id(id_red_privada)
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
        if self.usuario is None:
            return []
        else:
            private_network = self.get_private_network_by_id(private_network_id)
            return private_network.get_endpoints()

    def get_public_key(self):
        """
        Recupera la llave pública de Wireguard del orquestrador
        """
        return self.wg_public_key

    def get_allowed_ips(self, private_network_id):
        """
        Recupera las IPs permitidas de una red privada
        """
        private_network = self.get_private_network_by_id(private_network_id)
        return private_network.get_available_hosts()


    def get_wireguard_config(self):
        print("Configurando Wireguard...")
        print("Obteniendo la llave pública del servidor...")
        print("Llave pública del servidor: ", self.wg_public_key)
        print("Puerto Wireguard del servidor: ", self.wg_port)
        return self.wg_public_key, self.wg_port, self.public_ip

    def create_peer(self, public_key, allowed_ips, endpoint_ip_WG, listen_port, ip_cliente):
        print("Crear peer en el servidor")
        print(public_key, allowed_ips, endpoint_ip_WG, listen_port, ip_cliente)

        self.wg.create_peer(public_key, allowed_ips, ip_cliente, listen_port)
        print("IP de Wireguard asignada: ", endpoint_ip_WG)
        return endpoint_ip_WG


    def init_wireguard(self):
        print("Creando claves de Wireguard...")
        self.wg_private_key, self.wg_public_key = self.wg.create_keys()
        print("Llave pública de Wireguard del servidor: ", self.wg_public_key)
        # Crear la interfaz de Wireguard
        self.wg_ip = "10.0.0.1"
        self.wg_port = 51820
        self.wg.create_interface(self.wg_ip)

    def connect_peers(ip_i, ip_j, port_i, port_j):
        # Set Up IP Tables Rules on Host Z To allow traffic to be forwarded between host A and host B, you need to set up appropriate iptables rules on host Z.
        wg.setup_iptables(ip_i, ip_j)
        # Save the IP Tables Rules
        wg.save_iptables()

server = Servidor()
# Verifica que se ejecute como root
if os.geteuid() != 0:
    print("Necesitas ejecutar este script como root!")
    sys.exit(1)
server.init_wireguard()
print("Listening on port ",server.port)
server.iniciar()
