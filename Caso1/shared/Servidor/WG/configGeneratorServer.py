import subprocess
import os
import logging
from typing import Optional, Tuple, Dict, List, Union


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
                ["wg", "set", self.interface_name, "private-key", "/dev/stdin"],
                input=self.private_key.encode(),
                check=True
            )
            
            self._run_command(f"wg set {self.interface_name} listen-port {self.listen_port}")

            # Add peer if configuration provided
            if peer_config:
                self.add_peer(
                    public_key=peer_config['public_key'],
                    allowed_ips=peer_config['allowed_ips'],
                    endpoint_ip=peer_config['endpoint_ip'],
                    endpoint_port=peer_config['endpoint_port']
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
                allowed_ips: Union[str, List[str]], 
                endpoint_ip: str, 
                endpoint_port: int) -> None:
        """
        Add a peer to the WireGuard interface.
        
        Args:
            public_key: Peer's public key
            allowed_ips: Allowed IPs (string or list of strings)
            endpoint_ip: Peer's endpoint IP
            endpoint_port: Peer's listening port
            
        Raises:
            RuntimeError: If operation fails
            ValueError: If invalid allowed_ips format
        """
        try:
            # Normalize allowed_ips to comma-separated string
            if isinstance(allowed_ips, list):
                allowed_ips_str = ",".join(allowed_ips)
            elif isinstance(allowed_ips, str):
                allowed_ips_str = allowed_ips
            else:
                raise ValueError("allowed_ips must be string or list of strings")
            
            self.logger.info(f"Adding peer {public_key[:8]}...")
            
            cmd = (
                f"wg set {self.interface_name} peer {public_key} "
                f"allowed-ips {allowed_ips_str} "
                f"endpoint {endpoint_ip}:{endpoint_port}"
            )
            
            self._run_command(cmd)
            self.logger.info(f"Successfully added peer {public_key[:8]}")

        except ValueError as e:
            self.logger.error(f"Invalid allowed_ips format: {e}")
            raise
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to add peer: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

    def configure_firewall(self, local_ips: List[str] = None) -> None:
        """
        Configure firewall rules for WireGuard traffic.
        
        Args:
            local_ips: List of local IPs to allow (default allows any)
            
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
                "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
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
        return os.name == "posix"

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
            self._run_command(f"ip link set down dev {self.interface_name}")
            
            # Remove interface
            self._run_command(f"ip link delete dev {self.interface_name}")
            
            # Reset keys
            self.private_key = None
            self.public_key = None
            
            self.logger.info(f"Successfully cleared interface {self.interface_name}")
            return True

        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to clear interface: {e.stderr.strip()}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)