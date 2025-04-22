import subprocess
import os


def create_keys():
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

def create_wg_interface(ip_wg,listen_port, public_key, private_key):
    """
    Crea una interfaz de Wireguard.
    """
    print("Creando interfaz...")
    if os.system("ip link show wg10") == 0:
            print("La interfaz ya existe.")
    else:
        print("La interfaz no existe.")
        os.system(f"ip link add dev wg0 type wireguard")
        os.system(f"ip address add {ip_wg} dev wg0")

    # Configurar la interfaz
    # Construct the command
    command = [
        "wg", "set", "wg0",
        "listen-port", str(listen_port),
        "private-key", "/dev/stdin",
        "peer", public_key
    ]

    # Run the command and pass the private key as input
    subprocess.run(command, input=private_key.encode(), check=True)

    print("Interfaz creada!")
    print("Llave publica: ", public_key)

    os.system("ip link set up dev wg0")
    return private_key, public_key


def create_peer(public_key, allowed_ips, endpoint_ip, listen_port):
    # Añadir peer
    print("Añadiendo peer...")
    allowed_ips = allowed_ips[0]
    #wg set wg0 listen-port 51820 private-key /path/to/private-key peer ABCDEF... allowed-ips 192.168.88.0/24 endpoint 209.202.254.14:8172
    # sudo wg set wg0  peer pAY9t1yQPi4lVD84YULYhdiWGhECf2SRs7pll2Vnrgw= allowed-ips 192.168.2.0/24 endpoint 34.42.253.180:51820
    print(f"wg set wg0 peer {public_key} allowed-ips {allowed_ips} endpoint {endpoint_ip}:{listen_port}")
    os.system(f"wg set wg0 peer {public_key} allowed-ips {allowed_ips} endpoint {endpoint_ip}:{listen_port}")
    
def check_interface():
    """
    Verifica si la interfaz wg0 existe.
    """
    try:
        output = subprocess.check_output(["ip", "link", "show", "wg0"])
        return True
    except subprocess.CalledProcessError:
        return False