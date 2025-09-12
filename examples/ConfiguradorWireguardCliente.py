import subprocess
import os
import time
import logging
from typing import Optional, Tuple, List, Union


class ConfiguradorWireguardCliente:
    """
    Clase que configura Wireguard en el cliente con manejo seguro de operaciones y logging.
    """
    
    DEFAULT_INTERFACE = "wg0"
    DEFAULT_PORT = 51820

    def __init__(self, interface_name: str = DEFAULT_INTERFACE):
        """
        Inicializa el configurador de Wireguard.
        
        Args:
            interface_name: Nombre de la interfaz Wireguard (por defecto 'wg0')
        """
        self.interface_name = interface_name
        self.private_key: Optional[str] = None
        self.public_key: Optional[str] = None
        self.ip_wg: Optional[str] = None
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Configura y retorna un logger instance."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def create_keys(self) -> Tuple[str, str]:
        """
        Genera las claves pública y privada de Wireguard de manera segura.
        
        Returns:
            Tuple con (clave_privada, clave_publica)
            
        Raises:
            RuntimeError: Si falla la generación de claves
        """
        try:
            self.logger.info("Generando claves Wireguard...")
            
            # Generar clave privada
            private_key = subprocess.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()

            # Generar clave pública
            public_key = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()

            self.private_key = private_key
            self.public_key = public_key

            self.logger.info("Claves generadas exitosamente")
            return private_key, public_key

        except subprocess.CalledProcessError as e:
            error_msg = f"Error generando claves: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def create_wg_interface(self, ip_wg: str, 
                          peer_public_key: Optional[str] = None,
                          peer_allowed_ips: Optional[List[str]] = None,
                          peer_endpoint_ip: Optional[str] = None,
                          peer_listen_port: Optional[int] = None) -> bool:
        """
        Crea y configura una interfaz Wireguard.
        
        Args:
            ip_wg: Dirección IP para la interfaz (ej. '10.0.0.1/24')
            peer_*: Parámetros opcionales para configuración inicial de peer
            
        Returns:
            bool: True si la operación fue exitosa
            
        Raises:
            RuntimeError: Si el sistema no es compatible o falla la operación
        """
        if os.name != "posix":
            error_msg = "Sistema operativo no soportado (solo Linux)"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

        try:
            if self._interface_exists():
                self.logger.warning(f"La interfaz {self.interface_name} ya existe")
                return False

            self.logger.info(f"Creando interfaz {self.interface_name}...")
            
            # Crear interfaz
            self._run_command(f"ip link add dev {self.interface_name} type wireguard")
            self._run_command(f"ip address add {ip_wg} dev {self.interface_name}")
            self.ip_wg = ip_wg

            # Configurar interfaz
            if self.private_key:
                subprocess.run(
                    ["wg", "set", self.interface_name, "private-key", "/dev/stdin"],
                    input=self.private_key.encode(),
                    check=True
                )
            
            self._run_command(f"wg set {self.interface_name} listen-port {self.DEFAULT_PORT}")

            # Configurar peer si se proporcionan parámetros
            if all([peer_public_key, peer_allowed_ips, peer_endpoint_ip, peer_listen_port]):
                self.add_peer(
                    public_key=peer_public_key,
                    allowed_ips=peer_allowed_ips,
                    endpoint_ip=peer_endpoint_ip,
                    listen_port=peer_listen_port
                )

            self._run_command(f"ip link set up dev {self.interface_name}")
            
            # Esperar a que la interfaz esté lista
            time.sleep(1)
            
            self.logger.info(f"Interfaz {self.interface_name} creada exitosamente")
            return True

        except subprocess.CalledProcessError as e:
            error_msg = f"Error configurando interfaz: {e.stderr.strip()}"
            self.logger.error(error_msg)
            self._cleanup_interface()
            raise RuntimeError(error_msg)

    def add_peer(self, public_key: str, 
                allowed_ips: Union[str, List[str]], 
                endpoint_ip: str, 
                listen_port: int) -> None:
        """
        Añade un peer a la interfaz Wireguard.
        
        Args:
            public_key: Clave pública del peer
            allowed_ips: Lista de redes permitidas (ej. ['192.168.1.0/24']) o string
            endpoint_ip: IP del endpoint del peer
            listen_port: Puerto del peer
            
        Raises:
            RuntimeError: Si falla la operación
            ValueError: Si allowed_ips no es válido
        """
        try:
            # Normalizar allowed_ips
            if isinstance(allowed_ips, list):
                allowed_ips_str = ",".join(allowed_ips)
            elif isinstance(allowed_ips, str):
                allowed_ips_str = allowed_ips
            else:
                raise ValueError("allowed_ips debe ser string o lista de strings")
            
            self.logger.info(f"Añadiendo peer {public_key[:8]}...")
            
            cmd = (
                f"wg set {self.interface_name} peer {public_key} "
                f"allowed-ips {allowed_ips_str} "
                f"endpoint {endpoint_ip}:{listen_port}"
            )
            
            self._run_command(cmd)
            self.logger.info(f"Peer {public_key[:8]} añadido exitosamente")

        except ValueError as e:
            self.logger.error(f"Error en parámetros: {e}")
            raise
        except subprocess.CalledProcessError as e:
            error_msg = f"Error añadiendo peer: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def get_interface_ip(self) -> Optional[str]:
        """
        Obtiene la dirección IP actual de la interfaz Wireguard.
        
        Returns:
            str: La dirección IP con notación CIDR, o None si no se encuentra
        """
        try:
            result = subprocess.run(
                ["ip", "-br", "-4", "addr", "show", "dev", self.interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            # Formato: wg0 UP 10.0.0.2/24
            parts = result.stdout.strip().split()
            if len(parts) >= 3:
                self.ip_wg = parts[2]
                return self.ip_wg
            return None
        except subprocess.CalledProcessError:
            return None

    def change_interface_ip(self, new_ip: str, verify: bool = True) -> None:
        """
        Cambia la dirección IP de la interfaz Wireguard.
        
        Args:
            new_ip: Nueva dirección IP con notación CIDR (ej. '10.0.0.2/24')
            verify: Si verificar el cambio (default: True)
            
        Raises:
            RuntimeError: Si falla la operación
            ValueError: Si el formato de IP es inválido
        """
        if not self._validate_ip_format(new_ip):
            error_msg = f"Formato de IP inválido: {new_ip}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        if not self._interface_exists():
            error_msg = f"La interfaz {self.interface_name} no existe"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

        try:
            self.logger.info(f"Cambiando IP de {self.interface_name} a {new_ip}...")
            
            # Obtener IP actual para eliminarla
            current_ip = self.get_interface_ip()
            
            if current_ip:
                self._run_command(f"ip addr del {current_ip} dev {self.interface_name}")
            
            # Añadir nueva IP
            self._run_command(f"ip addr add {new_ip} dev {self.interface_name}")
            self.ip_wg = new_ip
            
            if verify:
                time.sleep(1)
                verified_ip = self.get_interface_ip()
                if verified_ip != new_ip:
                    self.logger.warning(f"Verificación fallida. Esperado: {new_ip}, Obtenido: {verified_ip}")
            
            self.logger.info(f"IP cambiada exitosamente a {new_ip}")

        except subprocess.CalledProcessError as e:
            error_msg = f"Error cambiando IP: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def _validate_ip_format(self, ip_address: str) -> bool:
        """
        Valida el formato de una dirección IP con notación CIDR.
        
        Args:
            ip_address: Dirección IP a validar
            
        Returns:
            bool: True si es válida, False en caso contrario
        """
        try:
            parts = ip_address.split('/')
            if len(parts) != 2:
                return False
            if not 0 <= int(parts[1]) <= 32:
                return False
            return True
        except (ValueError, IndexError):
            return False

    def _interface_exists(self) -> bool:
        """Verifica si la interfaz ya existe."""
        try:
            subprocess.run(
                ["ip", "link", "show", self.interface_name],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _run_command(self, command: str) -> None:
        """Ejecuta un comando de shell con manejo de errores."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            if result.stdout:
                self.logger.debug(result.stdout.strip())
        except subprocess.CalledProcessError as e:
            error_msg = f"Comando fallido: {command}\nError: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def _cleanup_interface(self) -> None:
        """Intenta limpiar la interfaz si la creación falla."""
        try:
            if self._interface_exists():
                self._run_command(f"ip link delete dev {self.interface_name}")
        except RuntimeError:
            pass  # No enmascarar el error original con errores de limpieza

    def clear_interface(self) -> bool:
        """
        Elimina completamente la interfaz WireGuard y limpia la configuración relacionada.
        
        Returns:
            bool: True si la interfaz fue eliminada, False si no existía
            
        Raises:
            RuntimeError: Si falla la eliminación
        """
        if not self._interface_exists():
            self.logger.info(f"La interfaz {self.interface_name} no existe")
            return False

        try:
            self.logger.info(f"Eliminando interfaz {self.interface_name}...")
            
            # Primero desactivar la interfaz
            self._run_command(f"ip link set down dev {self.interface_name}")
            
            # Eliminar la interfaz
            self._run_command(f"ip link delete dev {self.interface_name}")
            
            # Limpiar propiedades
            self.private_key = None
            self.public_key = None
            self.ip_wg = None
            
            self.logger.info(f"Interfaz {self.interface_name} eliminada correctamente")
            return True

        except subprocess.CalledProcessError as e:
            error_msg = f"Error al eliminar la interfaz: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def interface_up(self) -> None:
        """Activa la interfaz Wireguard."""
        if not self._interface_exists():
            raise RuntimeError(f"La interfaz {self.interface_name} no existe")
            
        try:
            self._run_command(f"ip link set up dev {self.interface_name}")
            self.logger.info(f"Interfaz {self.interface_name} activada")
        except subprocess.CalledProcessError as e:
            error_msg = f"Error activando interfaz: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def interface_down(self) -> None:
        """Desactiva la interfaz Wireguard."""
        if not self._interface_exists():
            raise RuntimeError(f"La interfaz {self.interface_name} no existe")
            
        try:
            self._run_command(f"ip link set down dev {self.interface_name}")
            self.logger.info(f"Interfaz {self.interface_name} desactivada")
        except subprocess.CalledProcessError as e:
            error_msg = f"Error desactivando interfaz: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def get_interface_status(self) -> str:
        """
        Obtiene el estado actual de la interfaz Wireguard.
        
        Returns:
            str: Estado de la interfaz ("up", "down", o "not found")
        """
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show", self.interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            if "UP" in result.stdout:
                return "up"
            return "down"
        except subprocess.CalledProcessError:
            return "not found"
        
    def up_interface(self) -> None:
        """
        Bring the WireGuard interface up (activate it).
        
        Raises:
            RuntimeError: If operation fails or interface doesn't exist
        """
        if not self._interface_exists():
            error_msg = f"Interface {self.interface_name} does not exist"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
            
        try:
            self.logger.info(f"Bringing interface {self.interface_name} up...")
            self._run_command(f"ip link set up dev {self.interface_name}")
            self.logger.info(f"Interface {self.interface_name} is now up")
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to bring interface up: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def down_interface(self) -> None:
        """
        Bring the WireGuard interface down (deactivate it).
        
        Raises:
            RuntimeError: If operation fails or interface doesn't exist
        """
        if not self._interface_exists():
            error_msg = f"Interface {self.interface_name} does not exist"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
            
        try:
            self.logger.info(f"Bringing interface {self.interface_name} down...")
            self._run_command(f"ip link set down dev {self.interface_name}")
            self.logger.info(f"Interface {self.interface_name} is now down")
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to bring interface down: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
        
    def generate_server_key(self) -> Tuple[str, str]:
        """
        Generate and store server's WireGuard private and public keys.
        This is a specialized version of create_keys() that ensures keys are stored in the instance.
        
        Returns:
            Tuple of (private_key, public_key)
            
        Raises:
            RuntimeError: If key generation fails
        """
        try:
            self.logger.info("Generating server WireGuard keys...")
            
            # Generate private key if not already exists
            if not self.private_key:
                self.private_key = subprocess.run(
                    ["wg", "genkey"],
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout.strip()
            
            # Generate public key from private key if not exists
            if not self.public_key:
                self.public_key = subprocess.run(
                    ["wg", "pubkey"],
                    input=self.private_key,
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout.strip()
            
            self.logger.info("Successfully generated server keys")
            self.logger.debug(f"Private key: {self.private_key[:8]}...")
            self.logger.debug(f"Public key: {self.public_key[:8]}...")
            
            return self.private_key, self.public_key

        except subprocess.CalledProcessError as e:
            error_msg = f"Server key generation failed: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)