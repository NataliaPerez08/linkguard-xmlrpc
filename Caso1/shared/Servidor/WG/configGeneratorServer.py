import subprocess
import os

"""
Script que genera una llave pública y privada de Wireguard y crea una interfaz wg.
parameters:
none
returns:
Private key, Public key
"""
def create_keys():
    """
    Genera las claves pública y privada de Wireguard.
    """
    print("Generando claves...")
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

"""
parameters:
ip_wg: IP de la interfaz wg.
public_key: Llave pública del servidor.
private_key: Llave privada del servidor.
peer_public_key: Llave pública del peer.
peer_allowed_ips: IPs permitidas del peer.
peer_endpoint_ip: IP del endpoint del peer.
peer_listen_port: Puerto del peer.

returns:
None
"""
def create_wg_interface(ip_wg, public_key, private_key, peer_public_key=None, peer_allowed_ips=None, peer_endpoint_ip=None, peer_listen_port=None):
    """
    Crea una interfaz de Wireguard.
    """
    print("Creando interfaz...")
    # Si es Linux
    if os.name == "posix":
        # Verificar si existe la interfaz
        if os.system("ip link show wg10") == 0:
            print("La interfaz ya existe.")
        else:
            os.system(f"ip link add dev wg10 type wireguard")
            os.system(f"ip address add {ip_wg} dev wg10")

        # Configurar la interfaz con las llaves  pública y privada
        subprocess.run(["wg", "set", "wg10", "private-key", "/dev/stdin"], input=private_key.encode(), check=True)
        os.system(f"wg set wg10 listen-port 51820")
        if peer_public_key is not None and peer_allowed_ips is not None and peer_endpoint_ip is not None and peer_listen_port is not None:
            os.system(f"wg set wg10 peer {peer_public_key} allowed-ips {peer_allowed_ips} endpoint {peer_endpoint_ip}:{peer_listen_port}")

        os.system("ip link set up dev wg10")
        
        return True
    else:
        print("Sistema operativo no soportado.")
        return False

def get_wg_state():
    """
    Obtiene el estado de Wireguard.
    """
    print("Obteniendo estado de Wireguard...")
    result = subprocess.run(["wg"], stdout=subprocess.PIPE).stdout.decode("utf-8")
    return result

def get_wg_interface():
    """
    Obtiene la interfaz de Wireguard.
    """
    print("Obteniendo interfaz de Wireguard...")
    os.system("ip a show wg10")

def get_wg_interface_config():
    """
    Obtiene la configuración de la interfaz de Wireguard.
    """
    print("Obteniendo configuración de la interfaz de Wireguard...")
    os.system("wg showconf wg10")


"""
parameters:
- public_key
- allowed_ip
- endpoint_ip
- listen_port
"""
def create_peer(public_key, allowed_ips, endpoint_ip, listen_port):
        # Añadir peer
        print("Añadiendo peer...")
        
        #wg set wg0 listen-port 51820 private-key /path/to/private-key peer ABCDEF... allowed-ips 192.168.88.0/24 endpoint 209.202.254.14:8172
        allowed_ips = "10.0.0.0/24"
        # sudo wg set wg10  peer pAY9t1yQPi4lVD84YULYhdiWGhECf2SRs7pll2Vnrgw= allowed-ips 192.168.2.0/24 endpoint 34.42.253.180:51820
        print(f"wg set wg10 peer {public_key} allowed-ips {allowed_ips} endpoint {endpoint_ip}:{listen_port}")
        os.system(f"wg set wg10 peer {public_key} allowed-ips {allowed_ips} endpoint {endpoint_ip}:{listen_port}")

def setup_iptables(ip_i, ip_j, port_i, port_j):
    """
    Configura iptables para permitir el tráfico de Wireguard.
    """
    print("Configurando iptables...")
    os.system(f"iptables -A INPUT -s {ip_i} -p udp --dport {port_i} -j ACCEPT")
    os.system(f"iptables -A INPUT -s {ip_j} -p udp --dport {port_j} -j ACCEPT")
    os.system("iptables -A FORWARD -i wg0 -j ACCEPT")
    os.system("iptables -A FORWARD -o wg0 -j ACCEPT")
    os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")

def save_iptables():
    """
    Guarda las reglas de iptables.
    """
    print("Guardando reglas de iptables...")
    os.system("iptables-save > /etc/iptables/rules.v4")