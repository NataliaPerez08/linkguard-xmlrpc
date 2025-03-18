FROM almalinux:9

# Actualiza el sistema e instala los paquetes necesarios
RUN dnf update -y && \
    dnf install -y git net-tools wireguard-tools iproute && \
    dnf install -y python3 python3-pip python3-scapy && \
    # Instalar netcat
    dnf install -y nmap-ncat && \
    dnf clean all

#RUN git clone https://github.com/NataliaPerez08/linkguard-xmlrpc.git

# Comando por defecto para mantener el contenedor en ejecución
CMD ["tail", "-f", "/dev/null"]

# Exponer el puerto 8000
EXPOSE 8000