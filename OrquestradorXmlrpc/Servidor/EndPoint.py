class Endpoint:
    def __init__(self, id_endpoint, name, private_network_id):
        self.id = id_endpoint
        self.name = name
        self.private_network_id = private_network_id
        self.wireguard_ip = ""
        self.wireguard_port = ""
        self.wireguard_private_key = ""
        self.wireguard_public_key = ""

        self.public_ip = ""

        self.config_wireguard = dict()

    def get_id(self):
        return self.id
    
    def get_name(self):
        return self.name
    
    def get_private_network_id(self):
        return self.private_network_id
    
    def get_wireguard_ip(self):
        return self.wireguard_ip
    
    def get_wireguard_port(self):
        return self.wireguard_port
    
    def get_wireguard_private_key(self):
        return self.wireguard_private_key
    
    def get_wireguard_public_key(self):
        return self.wireguard_public_key
    
    def get_public_ip(self):
        return self.public_ip
    
    def set_private_network_id(self, private_network_id):
        self.private_network_id = private_network_id

    def save_wireguard_config(self, config):
        self.config_wireguard = config
        
    def __str__(self) -> str:
        str_endpoint = "[Interface]\n"
        str_endpoint += "PrivateKey = " + self.wireguard_private_key + "\n"
        str_endpoint += "Address = " + self.wireguard_ip + "/32\n"
        str_endpoint += "ListenPort = " + self.wireguard_port + "\n"
        str_endpoint += "\n"
        str_endpoint += "[Peer]\n"
        str_endpoint += "PublicKey = " + self.config_wireguard["public_key"] + "\n"
        str_endpoint += "AllowedIPs = " + self.config_wireguard["allowed_ips"] + "\n"
        str_endpoint += "Endpoint = " + self.config_wireguard["public_ip"] + ":" + self.config_wireguard["port"] + "\n"
        return str_endpoint