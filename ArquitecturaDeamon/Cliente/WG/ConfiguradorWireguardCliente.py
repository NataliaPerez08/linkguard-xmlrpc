import subprocess
import os

class ConfiguradorWireguardCliente:
    def __init__(self):
        private_key, public_key = self.create_keys()
        self.private_key = private_key
        self.public_key = public_key
        
        self.listen_port = 51820

    def create_keys(self):
        """
        Genera las claves pública y privada de Wireguard.
        """
        #print("Generando claves...")
        # Generar clave privada
        private_key = subprocess.run(["wg", "genkey"], stdout=subprocess.PIPE)

        # Llave privada en bytes
        private_key = private_key.stdout

        # Generar clave pública
        public_key = subprocess.run(["wg", "pubkey"], input=private_key, stdout=subprocess.PIPE)

        public_key = public_key.stdout.decode("utf-8").strip()

        # De bytes a string
        private_key = private_key.decode("utf-8").strip()

        return private_key, public_key

    def create_wg_interface(self, ip_wg):
        """
        Crea una interfaz de Wireguard.
        """
        print("Creando interfaz...")
        # Si es Linux
        if os.name == "posix":
            print("La interfaz no existe.")
            os.system(f"ip link add dev wg0 type wireguard")
            os.system(f"ip address add {ip_wg} dev wg0")

            # Configurar la interfaz
            # Construct the command
            command = [
                "wg", "set", "wg0",
                "listen-port", str(self.listen_port),
                "private-key", "/dev/stdin",
                "peer", self.public_key
            ]

            # Run the command and pass the private key as input
            subprocess.run(command, input=self.private_key.encode(), check=True)

            print("Interfaz creada!")
            print("Llave publica: ", self.public_key)

            os.system("ip link set up dev wg0")
            return self.private_key, self.public_key
        else:
            print("Sistema operativo no soportado.")

    def check_interface(self):
        """
        Verifica si la interfaz de Wireguard existe.
        """
        print("Verificando interfaz...")
        if os.system("ip link show wg0") == 0:
            return True
        else:
            return False

    def create_peer(self, public_key, allowed_ips, endpoint_ip, listen_port, ip_servidor):
        # Añadir peer
        print("Añadiendo peer...")
        
        #wg set wg0 listen-port 51820 private-key /path/to/private-key peer ABCDEF... allowed-ips 192.168.88.0/24 endpoint 209.202.254.14:8172
        allowed_ips = "10.0.0.0/24"
        print("Creando peer...", public_key)
        # sudo wg set wg10  peer pAY9t1yQPi4lVD84YULYhdiWGhECf2SRs7pll2Vnrgw= allowed-ips 192.168.2.0/24 endpoint 34.42.253.180:51820
        print(f"wg set wg0 peer {public_key} allowed-ips {allowed_ips} endpoint {endpoint_ip}:{listen_port}")
        ossy = os.system(f"wg set wg0 peer {public_key} allowed-ips {allowed_ips} endpoint {endpoint_ip}:{listen_port}")
        print(type(ossy))
        
    
    def get_wg_state(self):
        """
        Obtiene el estado de Wireguard.
        """
        print("Obteniendo estado de Wireguard...")
        # Guardar resultado en una variable
        result = subprocess.run(["wg"], stdout=subprocess.PIPE).stdout.decode("utf-8")
        return result
        
    def get_wg_interface(self):
        """
        Obtiene la interfaz de Wireguard.
        """
        print("Obteniendo interfaz de Wireguard...")
        os.system("ip a show wg0")

    def get_wg_interface_config(self):
        """
        Obtiene la configuración de la interfaz de Wireguard.
        """
        print("Obteniendo configuración de la interfaz de Wireguard...")
        os.system("wg showconf wg0")
