import subprocess
import os
import logging
from typing import Optional, Tuple, Dict, List, Union
import time

class WireGuardConfigurator:
    """
    A comprehensive WireGuard configuration manager that handles interface creation,
    peer management, and firewall configuration with proper error handling.
    """

    def __init__(self, interface_name: str = "wg10", listen_port: int = 51820):
        """
        Initialize the WireGuard configurator.
        
        Args:
            interface_name: Name of the WireGuard interface (default: wg10)
            listen_port: Port for WireGuard to listen on (default: 51820)
        """
        self.interface_name = interface_name
        self.listen_port = listen_port
        self.private_key: Optional[str] = None
        self.public_key: Optional[str] = None
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Configure and return a logger instance."""
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
        Generate WireGuard public and private keys securely.
        
        Returns:
            Tuple of (private_key, public_key)
            
        Raises:
            RuntimeError: If key generation fails
        """
        try:
            self.logger.info("Generating WireGuard keys...")
            
            # Generate private key
            result = subprocess.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
                check=True
            )
            private_key = result.stdout.strip()
            
            # Generate public key
            result = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                check=True
            )
            public_key = result.stdout.strip()

            self.private_key = private_key
            self.public_key = public_key
            
            self.logger.info("Successfully generated WireGuard keys")
            return private_key, public_key

        except subprocess.CalledProcessError as e:
            error_msg = f"Key generation failed: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def create_interface(self, ip_wg: str, peer_config: Optional[Dict] = None) -> bool:
        """
        Create and configure a WireGuard interface.
        
        Args:
            ip_wg: IP address with CIDR notation for the interface (e.g., '10.0.0.1/24')
            peer_config: Optional peer configuration dictionary with keys:
                - public_key: Peer's public key
                - allowed_ips: List of allowed IPs (e.g., ['192.168.1.0/24'])
                - endpoint_ip: Peer's endpoint IP
                - endpoint_port: Peer's listening port
                
        Returns:
            bool: True if successful, False if interface already exists
            
        Raises:
            RuntimeError: If operation fails or unsupported OS
        """
        if not self._check_os_support():
            error_msg = "Unsupported operating system (Linux required)"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

        if self._interface_exists():
            self.logger.warning(f"Interface {self.interface_name} already exists")
            return False

        try:
            self.logger.info(f"Creating WireGuard interface {self.interface_name}...")
            
            # Create interface
            self._run_command(f"ip link add dev {self.interface_name} type wireguard")
            self._run_command(f"ip address add {ip_wg} dev {self.interface_name}")

            # Configure interface
            subprocess.run(
                ["wg", "set", self.interface_name, "listen-port", str(self.listen_port)],
                check=True
            )
            
            if self.private_key:
                subprocess.run(
                    ["wg", "set", self.interface_name, "private-key", "/dev/stdin"],
                    input=self.private_key.encode(),
                    check=True
                )
            
            # Add peer if configuration provided
            if peer_config:
                self.add_peer(
                    public_key=peer_config.get('public_key'),
                    allowed_ips=peer_config.get('allowed_ips', []),
                    endpoint_ip=peer_config.get('endpoint_ip'),
                    endpoint_port=peer_config.get('endpoint_port')
                )

            self._run_command(f"ip link set up dev {self.interface_name}")
            
            self.logger.info(f"Successfully created interface {self.interface_name}")
            return True

        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to create interface: {e.stderr.strip()}"
            self.logger.error(error_msg)
            # Attempt cleanup if something went wrong
            self._cleanup_interface()
            raise RuntimeError(error_msg)

    def add_peer(self, public_key: str, 
                allowed_ips: Union[str, List[str]] = None, 
                endpoint_ip: Optional[str] = None, 
                endpoint_port: Optional[int] = None) -> None:
        """
        Add a peer to the WireGuard interface.
        
        Args:
            public_key: Peer's public key
            allowed_ips: Allowed IPs (string or list of strings)
            endpoint_ip: Peer's endpoint IP (optional)
            endpoint_port: Peer's listening port (optional)
            
        Raises:
            RuntimeError: If operation fails
            ValueError: If invalid allowed_ips format or missing required params
        """
        if not public_key:
            raise ValueError("public_key is required")
            
        if not allowed_ips:
            allowed_ips = []
            
        try:
            # Normalize allowed_ips to comma-separated string
            if isinstance(allowed_ips, list):
                allowed_ips_str = ",".join(allowed_ips)
            elif isinstance(allowed_ips, str):
                allowed_ips_str = allowed_ips
            else:
                raise ValueError("allowed_ips must be string or list of strings")
            
            self.logger.info(f"Adding peer {public_key[:8]}...")
            
            cmd = [f"wg set {self.interface_name} peer {public_key} allowed-ips {allowed_ips_str}"]
            
            if endpoint_ip and endpoint_port:
                cmd.append(f"endpoint {endpoint_ip}:{endpoint_port}")
            
            self._run_command(" ".join(cmd))
            self.logger.info(f"Successfully added peer {public_key[:8]}")

        except ValueError as e:
            self.logger.error(f"Invalid configuration: {e}")
            raise
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to add peer: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def configure_firewall(self, local_ips: List[str] = None, external_interface: str = "eth0") -> None:
        """
        Configure firewall rules for WireGuard traffic.
        
        Args:
            local_ips: List of local IPs to allow (default allows any)
            external_interface: External network interface for NAT (default: eth0)
            
        Raises:
            RuntimeError: If operation fails
        """
        try:
            self.logger.info("Configuring firewall rules...")
            
            # Base rules
            rules = [
                f"iptables -A INPUT -p udp --dport {self.listen_port} -j ACCEPT",
                f"iptables -A FORWARD -i {self.interface_name} -j ACCEPT",
                f"iptables -A FORWARD -o {self.interface_name} -j ACCEPT",
                f"iptables -t nat -A POSTROUTING -o {external_interface} -j MASQUERADE"
            ]
            
            # Add rules for specific IPs if provided
            if local_ips:
                for ip in local_ips:
                    rules.insert(0, f"iptables -A INPUT -s {ip} -p udp --dport {self.listen_port} -j ACCEPT")

            for rule in rules:
                self._run_command(rule)
                
            self.logger.info("Successfully configured firewall rules")

        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to configure firewall: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def save_firewall_rules(self) -> None:
        """
        Save firewall rules to persistent storage.
        
        Raises:
            RuntimeError: If operation fails
        """
        try:
            self.logger.info("Saving firewall rules...")
            self._run_command("mkdir -p /etc/iptables")
            self._run_command("iptables-save > /etc/iptables/rules.v4")
            self._run_command("ip6tables-save > /etc/iptables/rules.v6")
            self.logger.info("Firewall rules saved successfully")
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to save firewall rules: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def remove_interface(self) -> None:
        """Remove the WireGuard interface if it exists."""
        if self._interface_exists():
            try:
                self.logger.info(f"Removing interface {self.interface_name}...")
                self._run_command(f"ip link delete dev {self.interface_name}")
                self.logger.info(f"Interface {self.interface_name} removed")
            except subprocess.CalledProcessError as e:
                error_msg = f"Failed to remove interface: {e.stderr.strip()}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

    def interface_up(self) -> None:
        """
        Bring the WireGuard interface up.
        
        Raises:
            RuntimeError: If operation fails or interface doesn't exist
        """
        if not self._interface_exists():
            raise RuntimeError(f"Interface {self.interface_name} does not exist")
            
        try:
            self._run_command(f"ip link set up dev {self.interface_name}")
            self.logger.info(f"Interface {self.interface_name} brought up")
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to bring interface up: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def interface_down(self) -> None:
        """
        Bring the WireGuard interface down.
        
        Raises:
            RuntimeError: If operation fails or interface doesn't exist
        """
        if not self._interface_exists():
            raise RuntimeError(f"Interface {self.interface_name} does not exist")
            
        try:
            self._run_command(f"ip link set down dev {self.interface_name}")
            self.logger.info(f"Interface {self.interface_name} brought down")
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to bring interface down: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def get_interface_status(self) -> str:
        """
        Get the current status of the WireGuard interface.
        
        Returns:
            str: Interface status ("up", "down", or "not found")
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
            else:
                return "down"
        except subprocess.CalledProcessError:
            return "not found"

    # Private helper methods
    def _interface_exists(self) -> bool:
        """Check if the WireGuard interface exists."""
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

    def _check_os_support(self) -> bool:
        """Check if the OS is supported (Linux)."""
        return os.name == "posix" and os.uname().sysname == "Linux"

    def _run_command(self, command: str) -> None:
        """
        Execute a shell command with error handling.
        
        Args:
            command: The command to execute
            
        Raises:
            RuntimeError: If command fails
        """
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
            error_msg = f"Command failed: {command}\nError: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def _cleanup_interface(self) -> None:
        """Attempt to clean up interface if creation fails."""
        try:
            if self._interface_exists():
                self._run_command(f"ip link delete dev {self.interface_name}")
        except RuntimeError:
            pass  # Don't mask original error with cleanup error

    def clear_interface(self) -> bool:
        """
        Completely remove the WireGuard interface and clean up related configuration.
        
        Returns:
            bool: True if interface was removed, False if it didn't exist
            
        Raises:
            RuntimeError: If removal fails
        """
        if not self._interface_exists():
            self.logger.info(f"Interface {self.interface_name} does not exist")
            return False

        try:
            self.logger.info(f"Clearing interface {self.interface_name}...")
            
            # Bring interface down first
            self.interface_down()
            
            # Remove interface
            self.remove_interface()
            
            # Reset keys
            self.private_key = None
            self.public_key = None
            
            self.logger.info(f"Successfully cleared interface {self.interface_name}")
            return True

        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to clear interface: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
        
    def generate_peer_keys(self) -> Tuple[str, str, str]:
        """
        Generate a new set of WireGuard keys for a peer (private key, public key, and preshared key).
        
        Returns:
            Tuple of (private_key, public_key, preshared_key)
            
        Raises:
            RuntimeError: If key generation fails
        """
        try:
            self.logger.info("Generating peer WireGuard keys...")
            
            # Generate private key
            result = subprocess.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
                check=True
            )
            private_key = result.stdout.strip()
            
            # Generate public key
            result = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                check=True
            )
            public_key = result.stdout.strip()
            
            # Generate preshared key
            result = subprocess.run(
                ["wg", "genpsk"],
                capture_output=True,
                text=True,
                check=True
            )
            preshared_key = result.stdout.strip()

            self.logger.info("Successfully generated peer keys")
            return private_key, public_key, preshared_key

        except subprocess.CalledProcessError as e:
            error_msg = f"Peer key generation failed: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
        
    def get_interface_ip(self) -> Optional[str]:
        """
        Get the current IP address of the WireGuard interface.
        
        Returns:
            str: The current IP address with CIDR notation, or None if not found
        """
        try:
            result = subprocess.run(
                ["ip", "-br", "-4", "addr", "show", "dev", self.interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            # El formato de salida es: wg0 UP 10.0.0.1/24
            parts = result.stdout.strip().split()
            if len(parts) >= 3:
                self.current_ip = parts[2]
                return self.current_ip
            return None
        except subprocess.CalledProcessError:
            return None

    def change_interface_ip(self, new_ip: str, verify: bool = True) -> None:
        """
        Change the IP address of the WireGuard interface.
        
        Args:
            new_ip: New IP address with CIDR notation (e.g., '10.0.0.2/24')
            verify: Whether to verify the IP change (default: True)
            
        Raises:
            RuntimeError: If operation fails or interface doesn't exist
            ValueError: If invalid IP format
        """
        if not self._validate_ip_format(new_ip):
            raise ValueError(f"Invalid IP address format: {new_ip}")

        if not self._interface_exists():
            raise RuntimeError(f"Interface {self.interface_name} does not exist")

        try:
            self.logger.info(f"Changing IP address of {self.interface_name} to {new_ip}...")
            
            # Get current IP to remove it
            current_ip = self.get_interface_ip()
            
            if current_ip:
                self._run_command(f"ip addr del {current_ip} dev {self.interface_name}")
            
            # Add new IP
            self._run_command(f"ip addr add {new_ip} dev {self.interface_name}")
            self.current_ip = new_ip
            
            if verify:
                # Dar tiempo al sistema para aplicar los cambios
                time.sleep(1)
                verified_ip = self.get_interface_ip()
                if verified_ip != new_ip:
                    self.logger.warning(f"IP verification failed. Expected {new_ip}, got {verified_ip}")
                    # No lanzar excepción, solo registrar advertencia
            
            self.logger.info(f"IP address changed to {new_ip}")

        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to change IP address: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def _validate_ip_format(self, ip_address: str) -> bool:
        """
        Validate the format of an IP address with CIDR notation.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Basic validation - could be enhanced with more strict checks
            parts = ip_address.split('/')
            if len(parts) != 2:
                return False
            if not 0 <= int(parts[1]) <= 32:
                return False
            return True
        except (ValueError, IndexError):
            return False
