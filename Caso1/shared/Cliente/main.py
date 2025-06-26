# Configurador CLI
import xmlrpc.client
import sys
import os
import logging

# Configuración de logger
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger('WireGuard-CLI')

# Constantes
DEFAULT_DAEMON_ADDRESS = "http://0.0.0.0:3041/"

class WireGuardCLI:
    def __init__(self, daemon_address=DEFAULT_DAEMON_ADDRESS):
        self.daemon = xmlrpc.client.ServerProxy(daemon_address)
        logger.info(f"Conectado al daemon en {daemon_address}")

    def registrar_usuario(self, nombre, email, password):
        logger.info(f"Registrando usuario: {nombre} {email}")
        result = self.daemon.register_user(nombre, email, password)
        if result:
            logger.info("Usuario registrado exitosamente")
            print("✓ Usuario registrado")
        else:
            logger.warning("Error al registrar usuario: correo ya existente")
            print("✗ Error: El correo ya está registrado")
        return result

    def identificar_usuario(self, email, password):
        logger.info(f"Identificando usuario: {email}")
        result = self.daemon.identify_me(email, password)
        if result:
            logger.info("Usuario identificado exitosamente")
            print("✓ Usuario identificado")
        else:
            logger.warning("Error en identificación: credenciales inválidas")
            print("✗ Error: Credenciales inválidas")
        return result

    def whoami(self):
        logger.info("Obteniendo usuario actual")
        result = self.daemon.whoami()
        if result:
            logger.info(f"Usuario actual: {result}")
            print(f"👤 Usuario actual: {result}")
        else:
            logger.warning("No hay usuario identificado")
            print("⚠️ No hay usuario identificado")
        return result

    def crear_red_privada(self, nombre, segmento=None):
        logger.info(f"Creando red privada: {nombre}")
        if segmento:
            logger.debug(f"Usando segmento de red: {segmento}")
            result = self.daemon.create_private_network(nombre, segmento)
        else:
            result = self.daemon.create_private_network(nombre)
        
        if result == -1:
            logger.error("Error al crear red privada")
            print("✗ Error al crear red privada")
            return False
        
        logger.info(f"Red creada con ID: {result}")
        print(f"✓ Red '{nombre}' creada - ID: {result}")
        return True

    def ver_redes_privadas(self):
        logger.info("Solicitando listado de redes privadas")
        result = self.daemon.get_private_networks()
        if not result:
            logger.warning("No se encontraron redes privadas")
            print("No hay redes privadas disponibles")
            return
        
        print("\n🔐 Redes Privadas:")
        for i, red in enumerate(result, 1):
            print(red)
        return result

    def ver_endpoints(self, id_red_privada):
        logger.info(f"Solicitando endpoints para red ID: {id_red_privada}")
        result = self.daemon.get_endpoints(id_red_privada)
        if not result:
            logger.warning(f"No se encontraron endpoints para red {id_red_privada}")
            print("No hay endpoints disponibles")
            return
        
        print(f"\n🔌 Endpoints para red {id_red_privada}:")
        for i, endpoint in enumerate(result, 1):
            print(f"  {i}. {endpoint['nombre']} (ID: {endpoint['id']})")
        return result

    def conectar_endpoint(self, id_endpoint, id_red_privada):
        logger.info(f"Conectando endpoint {id_endpoint} en red {id_red_privada}")
        try:
            self.daemon.connect_endpoint(id_endpoint, id_red_privada)
            logger.info("Solicitud de conexión enviada")
            print("✓ Solicitud de conexión enviada")
        except Exception as e:
            logger.error(f"Error en conexión: {str(e)}")
            print(f"✗ Error en conexión: {str(e)}")

    def conectar_endpoint_directo(self, ip_endpoint, puerto_endpoint):
        logger.info(f"Conectando directamente a {ip_endpoint}:{puerto_endpoint}")
        try:
            self.daemon.test_connection(ip_endpoint, puerto_endpoint)
            logger.info("Prueba de conexión directa iniciada")
            print("✓ Prueba de conexión iniciada")
        except Exception as e:
            logger.error(f"Error en conexión directa: {str(e)}")
            print(f"✗ Error en conexión: {str(e)}")

    def registrar_como_peer(self, nombre, id_red_privada, ip_cliente, puerto_cliente):
        logger.info(f"Registrando peer: {nombre} en red {id_red_privada}")
        if os.geteuid() != 0:
            logger.error("Se requieren permisos de administrador")
            print("✗ Error: Se requieren permisos de administrador")
            return False
        
        result = self.daemon.configure_as_peer(nombre, id_red_privada, ip_cliente, puerto_cliente)
        if result == -1:
            logger.error("Error al configurar peer")
            print("✗ Error al configurar peer")
            return False
        
        logger.info("Peer configurado exitosamente")
        print("✓ Peer configurado exitosamente")
        return True

    def cerrar_sesion(self):
        logger.info("Cerrando sesión")
        result = self.daemon.close_session()
        if result:
            logger.info("Sesión cerrada")
            print("✓ Sesión cerrada")
        else:
            logger.warning("Error al cerrar sesión")
            print("✗ Error al cerrar sesión")
        return result

    def obtener_clave_publica(self):
        logger.info("Solicitando clave pública del cliente")
        try:
            result = self.daemon.get_client_public_key()
            print(f"🔑 Clave pública: {result}")
            return result
        except AttributeError:
            logger.error("Método no implementado en el daemon")
            print("✗ Error: Función no disponible")
            return None

# Mapeo de comandos a funciones
COMMAND_MAP = {
    "registrar_usuario": {
        "func": "registrar_usuario",
        "args": 3,
        "desc": "Registrar nuevo usuario: <nombre> <email> <password>"
    },
    "identificar_usuario": {
        "func": "identificar_usuario",
        "args": 2,
        "desc": "Identificar usuario: <email> <password>"
    },
    "whoami": {
        "func": "whoami",
        "args": 0,
        "desc": "Mostrar usuario actual"
    },
    "crear_red_privada": {
        "func": "crear_red_privada",
        "args": (1, 2),
        "desc": "Crear red privada: <nombre> [segmento_red]"
    },
    "ver_redes_privadas": {
        "func": "ver_redes_privadas",
        "args": 0,
        "desc": "Listar redes privadas disponibles"
    },
    "ver_endpoints": {
        "func": "ver_endpoints",
        "args": 1,
        "desc": "Ver endpoints de una red: <id_red_privada>"
    },
    "conectar_endpoint": {
        "func": "conectar_endpoint",
        "args": 2,
        "desc": "Conectar a endpoint: <id_endpoint> <id_red_privada>"
    },
    "conectar_endpoint_directo": {
        "func": "conectar_endpoint_directo",
        "args": 2,
        "desc": "Conexión directa: <ip_wg_endpoint> <puerto_wg_endpoint>"
    },
    "registrar_como_peer": {
        "func": "registrar_como_peer",
        "args": 4,
        "desc": "Registrar como peer: <nombre> <id_red_privada> <ip_cliente> <puerto_cliente>"
    },
    "obtener_clave_publica_cliente": {
        "func": "obtener_clave_publica",
        "args": 0,
        "desc": "Obtener clave pública del cliente"
    },
    "cerrar_sesion": {
        "func": "cerrar_sesion",
        "args": 0,
        "desc": "Cerrar sesión actual"
    }
}

def mostrar_ayuda():
    print("\n🔧 WireGuard CLI - Comandos disponibles:")
    for cmd, info in COMMAND_MAP.items():
        print(f"  {cmd.ljust(30)} {info['desc']}")
    print("\n💡 Ejemplo: python cli.py registrar_usuario 'Juan Perez' juan@mail.com password123")
    print("💡 Ejemplo: python cli.py crear_red_privada 'Mi Red Privada'")
    print("💡 Ejemplo: python cli.py ver_redes_privadas")

def main():
    if len(sys.argv) < 2:
        mostrar_ayuda()
        return

    comando = sys.argv[1]
    cli = WireGuardCLI()

    if comando not in COMMAND_MAP:
        logger.error(f"Comando no reconocido: {comando}")
        print(f"✗ Comando no reconocido: {comando}")
        mostrar_ayuda()
        return

    cmd_info = COMMAND_MAP[comando]
    args_esperados = cmd_info["args"]
    args_recibidos = len(sys.argv) - 2  # Restamos comando y nombre de script
    
    # Validar número de argumentos
    if isinstance(args_esperados, tuple):
        if not (args_esperados[0] <= args_recibidos <= args_esperados[1]):
            logger.error(f"Argumentos incorrectos para {comando}")
            print(f"✗ Uso: {cmd_info['desc']}")
            return
    elif args_recibidos != args_esperados:
        logger.error(f"Argumentos incorrectos para {comando}")
        print(f"✗ Uso: {cmd_info['desc']}")
        return

    # Ejecutar comando
    try:
        func = getattr(cli, cmd_info["func"])
        func(*sys.argv[2:2+args_recibidos])
    except xmlrpc.client.Fault as e:
        logger.error(f"Error en servidor: {e.faultString}")
        print(f"✗ Error en servidor: {e.faultString}")
    except Exception as e:
        logger.exception(f"Error inesperado: {str(e)}")
        print(f"✗ Error inesperado: {str(e)}")

if __name__ == "__main__":
    main()