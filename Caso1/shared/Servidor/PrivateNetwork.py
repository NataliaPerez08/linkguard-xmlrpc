import ipaddress
from EndPoint import Endpoint

class PrivateNetwork:
    def __init__(self, id_red, name, ip_addr, mask_network):
        self.id = id_red
        self.name = name
        
        self.mask_network = mask_network
        self.ip_addr = ipaddress.IPv4Network(f"{ip_addr}/{mask_network}")
        
        self.available_hosts = self.calcule_network_range()
        self.num_endpoints = 0
        
        # Diccionario de endpoints {id: Endpoint}
        self.endpoints = dict()

    def get_id(self):
        return str(self.id)
    
    def get_name(self):
        return self.name
    
    def get_endpoints(self):
        return self.endpoints
    
    def get_ip_addr(self):
        return self.ip_addr
    
    def get_mask_network(self):
        return self.mask_network
    
    def get_available_hosts(self):
        if len(self.available_hosts) == 0:
            return []
        return [str(host) for host in self.available_hosts]
    
    def add_endpoint(self, endpoint):
        self.endpoints[str(endpoint.id)] = endpoint

    def get_network_mask(self):
        return self.ip_addr.netmask

    def set_ip_addr(self, ip_addr):
        self.ip_addr = ipaddress.IPv4Network(ip_addr)

    def set_network_mask(self, mask_network):
        self.mask_network = mask_network
        ip = self.ip_addr.exploded.split('/')[0]
        self.ip_addr = ipaddress.IPv4Network(f"{ip}/{mask_network}")

    def calcule_network_range(self):
        hosts = list(self.ip_addr.hosts())
        self.available_hosts = hosts.pop(0)
        return hosts
    
    def calculate_next_host(self):
        print("Calculando siguiente dirección IP disponible...")
        if len(self.available_hosts) == 0:
            print("No hay direcciones IP disponibles!")
            return None
        next_host = self.available_hosts.pop(0)
        return str(next_host)
    
    def create_endpoint(self, name) -> Endpoint:
        print("Creando endpoint... en la red privada: " + self.name)
        endpoint = Endpoint(id_endpoint=self.num_endpoints, name=name, private_network_id=self.id)
        
        endpoint.wireguard_ip = self.calculate_next_host()
        endpoint.wireguard_port = "51820"
        
        self.add_endpoint(endpoint)
        
        self.num_endpoints += 1
        return endpoint 
    
    def get_endpoint_by_id(self, endpoint_id):
        try:
            # Diccionario de endpoints self.endpoints {id: Endpoint}
            endpoint = self.endpoints[endpoint_id]
            return endpoint
        except:
            return -1
            
        

    def __str__(self):
        return "ID: " + str(self.id) + " IP Address: " + str(self.ip_addr) + " Mask Network: " + str(self.mask_network) 