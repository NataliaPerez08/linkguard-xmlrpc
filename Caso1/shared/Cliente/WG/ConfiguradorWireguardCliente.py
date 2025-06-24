import subprocess
import os
from typing import Optional, Tuple, List


class ConfiguradorWireguardCliente:
    """
    Clase que configura Wireguard en el cliente con manejo seguro de operaciones.
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

    def create_keys(self) -> Tuple[str, str]:
        """
        Genera las claves pública y privada de Wireguard de manera segura.
        
        Returns:
            Tuple con (clave_privada, clave_publica)
            
        Raises:
            subprocess.CalledProcessError: Si falla la generación de claves
        """
        try:
            # Generar clave privada
            private_key = subprocess.run(
                ["wg", "genkey"],
                stdout=subprocess.PIPE,
                check=True
            ).stdout

            # Generar clave pública
            public_key = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                stdout=subprocess.PIPE,
                check=True
            ).stdout.decode("utf-8").strip()

            # Convertir y almacenar las claves
            self.private_key = private_key.decode("utf-8").strip()
            self.public_key = public_key

            return self.private_key, self.public_key

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error generando claves Wireguard: {e}")

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
            raise RuntimeError("Sistema operativo no soportado (solo Linux)")

        try:
            if self._interface_exists():
                print(f"La interfaz {self.interface_name} ya existe.")
                return False

            print(f"Creando interfaz {self.interface_name}...")
            
            # Crear interfaz
            self._run_command(f"ip link add dev {self.interface_name} type wireguard")
            self._run_command(f"ip address add {ip_wg} dev {self.interface_name}")
            self.ip_wg = ip_wg

            # Configurar interfaz
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
            return True

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error configurando interfaz Wireguard: {e}")

    def add_peer(self, public_key: str, 
                allowed_ips: List[str], 
                endpoint_ip: str, 
                listen_port: int) -> None:
        """
        Añade un peer a la interfaz Wireguard.
        
        Args:
            public_key: Clave pública del peer
            allowed_ips: Lista de redes permitidas (ej. ['192.168.1.0/24'])
            endpoint_ip: IP del endpoint del peer
            listen_port: Puerto del peer
            
        Raises:
            RuntimeError: Si falla la operación
        """
        try:
            if not isinstance(allowed_ips, list):
                raise ValueError("allowed_ips debe ser una lista")
                
            allowed_ips_str = ",".join(allowed_ips)
            
            cmd = (
                f"wg set {self.interface_name} peer {public_key} "
                f"allowed-ips {allowed_ips_str} "
                f"endpoint {endpoint_ip}:{listen_port}"
            )
            
            print(f"Añadiendo peer: {cmd}")
            self._run_command(cmd)
            
        except (subprocess.CalledProcessError, ValueError) as e:
            raise RuntimeError(f"Error añadiendo peer: {e}")

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
            subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            error_msg = f"Comando fallido: {command}\nError: {e.stderr.decode().strip()}"
            raise RuntimeError(error_msg)

    def cleanup(self) -> None:
        """Elimina la interfaz Wireguard."""
        try:
            if self._interface_exists():
                self._run_command(f"ip link delete dev {self.interface_name}")
                print(f"Interfaz {self.interface_name} eliminada")
        except RuntimeError as e:
            print(f"Error al limpiar: {e}")