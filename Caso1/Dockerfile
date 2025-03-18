FROM almalinux:9

# Actualiza el sistema e instala los paquetes necesarios
RUN dnf update -y && \
    dnf install -y git net-tools wireguard-tools iproute && \
    dnf clean all

# Comando por defecto para mantener el contenedor en ejecución
CMD ["tail", "-f", "/dev/null"]