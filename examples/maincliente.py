from ConfiguradorWireguardCliente import ConfiguradorWireguardCliente
# Configuración básica
cliente = ConfiguradorWireguardCliente("wg-client")

# Generar claves
priv, pub = cliente.create_keys()

# Generar llaves del servidor
private_key, public_key = cliente.generate_server_key()

# Las llaves quedan almacenadas en la instancia
print(f"Private key stored: {cliente.private_key[:8]}...")
print(f"Public key stored: {cliente.public_key[:8]}...")


# Crear interfaz
cliente.create_wg_interface(
    ip_wg="10.0.0.2/24",
    peer_public_key="{public_key}",
    peer_allowed_ips=["10.0.0.0/24"],
    peer_endpoint_ip="1.2.3.4",  # IP pública del servidor
    peer_listen_port=51820
)

# Cambiar IP si es necesario
cliente.change_interface_ip("10.0.0.3/24")

# Verificar estado
print(f"Estado: {cliente.get_interface_status()}")
print(f"IP actual: {cliente.get_interface_ip()}")

# interface up
cliente.up_interface()
# Verificar estado después de activar
print(f"Estado después de activar: {cliente.get_interface_status()}")

cliente.down_interface()
# Verificar estado después de desactivar
print(f"Estado después de desactivar: {cliente.get_interface_status()}")


# Cambiar IP si es necesario
cliente.change_interface_ip("172.10.3/24")

cliente.change_interface_ip("172.15.3/24")


# Limpiar al final
cliente.clear_interface()