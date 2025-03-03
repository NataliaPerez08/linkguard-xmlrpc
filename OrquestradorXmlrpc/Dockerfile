# Crear una imagen de debian
FROM debian:latest
# Instalar git
RUN apt-get update && apt-get install -y git

# Instalar wireguard
RUN apt-get install -y wireguard

# Instalar python
RUN apt-get install -y python3 python3-pip

# Instalar librerias de python
RUN apt-get install -y python3-aioxmlrpc 

# Instalar scapy
RUN apt-get install -y python3-scapy

# git clone https://github.com/NataliaPerez08/docsTesis.git
RUN git clone https://github.com/NataliaPerez08/docsTesis.git

# Cambiar de directorio OrquestradorXmlrpc/Servidor/
WORKDIR /docsTesis/OrquestradorXmlrpc/Servidor/

# Ejecutar el servidor como administrador
CMD ["python3", "server.py"]

# Exponer el puerto 8000
EXPOSE 8000