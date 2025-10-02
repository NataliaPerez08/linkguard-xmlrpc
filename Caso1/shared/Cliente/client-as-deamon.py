# Daemon del cliente
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
from sys import exit, argv

# Constantes
DEFAULT_SERVER_PORT = 8000
DEFAULT_LOCAL_PORT = 3041
DEFAULT_LOCAL_ADDRESS = "0.0.0.0"
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = logging.INFO

class ClientAsDeamon:
    """
    Clase que representa al cliente como un daemon
    """
    def __init__(self, dir_servidor, public_ip, port_local=DEFAULT_LOCAL_PORT, wg_ip="100.10.0.2", wg_port=51820):
        # Configurar logger
        self._setup_logger()
        
        self.orquestador = None
        self.wg = None
        # Servidor en la nube
        self.dir_servidor = f"http://{dir_servidor}:{DEFAULT_SERVER_PORT}/"
        self.orquestador = xmlrpc.client.ServerProxy(self.dir_servidor, allow_none=True)
        # Servidor local
        self.dir_local = DEFAULT_LOCAL_ADDRESS
        self.port_local = port_local
        self.wg_public_key = None
        self.wg_private_key = None
        self.wg_ip = wg_ip
        self.wg_port = wg_port
        self.actual_user = None
        self.public_ip = public_ip
        
        # Create server
        self.xmlrpc_server = SimpleXMLRPCServer((self.dir_local, self.port_local), logRequests=True)
        # Iniciar configurador de Wireguard
        self.wg = ConfiguradorWireguardCliente.ConfiguradorWireguardCliente()
        
        self.logger.info(f"Cliente daemon inicializado. Servidor en {self.dir_servidor}, escuchando en {self.dir_local}:{self.port_local}")

    def _setup_logger(self):
        """Configura el logger para la clase"""
        self.logger = logging.getLogger('ClientDaemon')
        self.logger.setLevel(LOG_LEVEL)
        
        # Crear formateador
        formatter = logging.Formatter(LOG_FORMAT)
        
        # Crear handler para consola
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        
        # Añadir handler al logger
        if not self.logger.handlers:
            self.logger.addHandler(ch)
        
        # Logger específico para XML-RPC
        self.xmlrpc_logger = logging.getLogger('xmlrpc.server')
        self.xmlrpc_logger.setLevel(LOG_LEVEL)
        if not self.xmlrpc_logger.handlers:
            self.xmlrpc_logger.addHandler(ch)

    def start_server(self):
        """
        Inicia el servidor XML-RPC
        """
        self.logger.info("Iniciando servidor XML-RPC...")
        # Create keys
        self.wg_private_key, self.wg_public_key = self.wg.create_keys()
        self.xmlrpc_server.register_instance(self)
        self.logger.info(f"Servidor XML-RPC iniciado en {self.dir_local}:{self.port_local}")
        self.xmlrpc_server.serve_forever()

    def register_user(self, name, email, password):
        """
        Registra un usuario en el servidor
        """
        self.logger.info(f"Registrando usuario: {name} {email}")
        is_register = self.orquestador.register_user(name, email, password)
        if not is_register:
            self.logger.warning("Error al registrar el usuario! El correo ya está registrado")
            return False
        self.logger.info("Usuario registrado exitosamente")
        return True

    def identify_me(self, email, password):
        """
        Identifica un usuario en el servidor
        """
        self.logger.info(f"Intentando identificación para usuario: {email}")
        is_identified = self.orquestador.identify_user(email, password)
        if not is_identified:
            self.logger.warning("Identificación fallida")
            return False
        self.logger.info("Identificación exitosa")
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
        self.logger.info(f"Creando red privada: {nombre}")
        private_network_id = self.orquestador.create_private_network(nombre)
        if private_network_id == -1:
            self.logger.warning("Error al crear red privada")
            return -1
        self.logger.info(f"Red privada creada con ID: {private_network_id}")
        return private_network_id

    def get_private_networks(self):
        """
        Recupera las redes privadas del servidor
        """
        self.logger.info("Obteniendo redes privadas")
        priv_net = self.orquestador.get_private_networks()
        return priv_net

    def get_endpoints(self, id_red_privada):
        """
        Obtiene los endpoints de una red privada
        """
        self.logger.info(f"Obteniendo endpoints para red privada ID: {id_red_privada}")
        endpoints = self.orquestador.get_endpoints(id_red_privada)
        return endpoints

    def connect_endpoint(self, id_endpoint, id_red_privada):
        self.logger.info(f"Conectando endpoint ID: {id_endpoint} en red privada ID: {id_red_privada}")
        # Encontrar la red privada
        private_network = self.orquestador.get_private_network_by_id(id_red_privada)

        if private_network == -1:
            self.logger.error("No se encontró la red privada")
            return

        # Encontrar dispositivo en la red
        endpoint = private_network.get_endpoint_by_id(id_endpoint)

        if endpoint == -1:
            self.logger.error("No se encontró el Endpoint")
            return

        self.logger.info(f"Endpoint encontrado: {endpoint}")
        self.logger.info(f"Red privada encontrada: {private_network}")
        verificar_conectividad(endpoint.ip_addr, private_network.last_host_assigned)

    def test_connection(self, ip_endpoint, puerto_endpoint):
        self.logger.info(f"Probando conexión directa con {ip_endpoint}:{puerto_endpoint}")
        verificar_conectividad(ip_endpoint)

    def close_session(self):
        self.logger.info("Cerrando sesión")
        # Cerrar el servidor XML-RPC
        result = self.orquestador.close_session()
        # Limpiar configuraciones de Wireguard
        if self.wg:
            self.wg.clear_interface()
            self.logger.info("Interfaz Wireguard eliminada")
        else:
            self.logger.warning("No se encontró interfaz Wireguard para eliminar")
        return result

    def init_wireguard_interface(self, ip_cliente):
        self.logger.info("Inicializando interfaz Wireguard")
        wg_private_key, self.wg_public_key = self.wg.create_keys()
        self.logger.debug(f"Clave privada: {wg_private_key}")
        self.logger.debug(f"Clave pública: {self.wg_public_key}")

        self.wg.create_wg_interface(ip_cliente)
        self.logger.info("Interfaz Wireguard inicializada")

    def configure_as_peer(self, nombre_endpoint, id_red_privada, ip_cliente, listen_port):
        self.logger.info(f"Configurando como peer: {nombre_endpoint} en red {id_red_privada}")
        endpoint_ip_WG, id_endpoint = self.orquestador.create_endpoint(id_red_privada, nombre_endpoint)
        if endpoint_ip_WG == -1:
            self.logger.error("Error al configurar el peer!")
            return -1
        self.logger.info(f"IP de Wireguard asignada: {endpoint_ip_WG}")

        # Verificar si la interfaz existe
        self.logger.info("Creando nueva interfaz Wireguard")
        self.init_wireguard_interface(self.public_ip)

        # Configurar peer en local
        self.logger.info("Obteniendo configuración del servidor...")
        allowed_ips = self.orquestador.get_allowed_ips(id_red_privada)
        self.logger.debug(f"Allowed IPs: {allowed_ips}")
        
        wg_o_pk, wg_o_port, wg_o_ip = self.orquestador.get_wireguard_config()
        self.logger.debug(f"Configuración del servidor - Clave: {wg_o_pk}, Puerto: {wg_o_port}, IP: {wg_o_ip}")

        self.logger.info("Creando peer local...")
        result = self.wg.add_peer(wg_o_pk, allowed_ips, wg_o_ip, wg_o_port)
        self.logger.info("Peer local creado")

        # Registrar peer en el servidor
        self.logger.info(f"Registrando peer en servidor con clave: {self.wg_public_key}")
        ip_wg_peer = self.orquestador.create_peer(self.wg_public_key, allowed_ips, endpoint_ip_WG, listen_port, ip_cliente)
        
        result = self.orquestador.complete_endpoint(id_red_privada, id_endpoint, 
                                                  self.wg_public_key, allowed_ips, 
                                                  ip_cliente, listen_port)
        self.logger.debug(f"Resultado completar endpoint: {result}")

        return ip_wg_peer

    def register_peer(self, public_key, allowed_ips, ip_cliente, listen_port):
        self.logger.info(f"Registrando nuevo peer con IP: {ip_cliente}")
        endpoint_ip_WG = self.orquestador.create_peer(public_key, allowed_ips, ip_cliente, listen_port)
        if endpoint_ip_WG == -1:
            self.logger.error("Error al registrar peer en servidor")
            return
        self.logger.info(f"Peer registrado con IP: {endpoint_ip_WG}")
        
        self.logger.info("Registrando peer localmente...")
        result = self.wg.add_peer(public_key, allowed_ips, ip_cliente, listen_port)
        self.logger.info("Peer local registrado")
        return result


if __name__ == "__main__":
    if geteuid() != 0:
        print("Se necesita permisos de administrador para ejecutar el servidor")
        exit()
    
    if len(argv) < 3:
        print("Ingresa la IP del orquestador!")
        print("Ingresa la IP del orquestador!")
        exit()

    # Configuración
    SERVER_ADDRESS = argv[1]#"localhost"  # Cambiar por la dirección del servidor
    CLIENT_PUBLIC_IP = argv[2]#"0.0.0.0"  # Cambiar por la IP pública del cliente
    
    client_as_deamon = ClientAsDeamon(SERVER_ADDRESS, CLIENT_PUBLIC_IP) 
    client_as_deamon.start_server()
