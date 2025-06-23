import os
import platform
import subprocess

def verificar_conectividad(direccion_ip):
    """
    Verifica si una IP es alcanzable por medio de un ping sin usar Scapy.
    
    Args:
        direccion_ip (str): La dirección IP a la que se quiere hacer ping.
    """
    # Determinar el sistema operativo para ajustar los parámetros del ping
    sistema_operativo = platform.system().lower()
    
    try:
        if sistema_operativo == "windows":
            # Para Windows: 1 ping con timeout de 2000ms
            comando = ["ping", "-n", "1", "-w", "2000", direccion_ip]
        else:
            # Para Linux/Mac: 1 ping con timeout de 2 segundos
            comando = ["ping", "-c", "1", "-W", "2", direccion_ip]
        
        # Ejecutar el comando y capturar la salida
        salida = subprocess.run(comando, 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True)
        
        # Verificar el resultado
        if salida.returncode == 0:
            print(f"La conectividad con {direccion_ip} está activa.")
        else:
            print(f"No se pudo establecer la conectividad con {direccion_ip}")
            
    except Exception as e:
        print(f"Error al ejecutar el comando ping: {e}")

# Ejemplo de uso
if __name__ == "__main__":
    verificar_conectividad("8.8.8.8")  # Google DNS