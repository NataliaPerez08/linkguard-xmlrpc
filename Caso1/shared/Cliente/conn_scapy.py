from scapy.all import *

# Verifica si una ip es alcanzable por medio de un ping
def verificar_conectividad(direccion_ip):
    # Construir un paquete ICMP (ping) con el destino especificado
    paquete_ping = IP(dst=direccion_ip) / ICMP()

    try:
        # Enviar el paquete ICMP y esperar una respuesta
        respuesta = sr1(paquete_ping, timeout=2, verbose=False)

        # Verificar si se recibió una respuesta
        if respuesta and respuesta.haslayer(ICMP):
            print(f"La conectividad con {direccion_ip} está activa.")
        else:
            print(f"No se pudo establecer la conectividad con {direccion_ip}")

    except Exception as e:
        print(f"Error al enviar o recibir paquete ICMP: {e}")
