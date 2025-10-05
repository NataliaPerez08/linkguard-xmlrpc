FROM almalinux:9

# Paquetes base y cliente SSH
RUN dnf -y update && \
    dnf -y install \
      git \
      net-tools \
      iproute \
      iputils \
      wireguard-tools \
      python3 python3-pip \
      python3-scapy \
      nmap-ncat \
      openssh-clients \
      jq \
      which \
      procps-ng \
    && dnf clean all

# Directorios de trabajo
RUN mkdir -p /shared/tests/artifacts /shared/WG/Cliente

# Variables por defecto (puedes overridear al correr el contenedor)
ENV SERVER_IP=172.20.0.10 \
    SERVER_PORT=8080 \
    ALMA2_IP=172.20.0.11 \
    ALMA3_IP=172.20.0.12 \
    SSH_USER=tester \
    SSH_PORT=22 \
    SSH_KEY_PATH=/shared/tests/id_ed25519

# Mantener vivo para debug
CMD ["tail", "-f", "/dev/null"]

# Puerto de app si
EXPOSE 8080