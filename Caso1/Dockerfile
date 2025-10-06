FROM almalinux:9

# Paquetes base + networking + iptables/nftables
RUN dnf -y update && \
    dnf -y install \
      git \
      net-tools \
      iproute \
      iputils \
      wireguard-tools \
      iptables \
      nftables \
      python3 python3-pip \
      python3-scapy \
      nmap-ncat \
      openssh-clients \
      jq \
      which \
      procps-ng && \
    dnf clean all

# (Opcional, normalmente no hace falta en EL9, pero si quieres forzar backend nft)
RUN alternatives --set iptables /usr/sbin/iptables-nft || true

# Directorios de trabajo
RUN mkdir -p /shared/tests/artifacts /shared/Cliente

# Variables por defecto
ENV SERVER_IP=172.20.0.10 \
    SERVER_PORT=8000 \
    ALMA2_IP=172.20.0.11 \
    ALMA3_IP=172.20.0.12

# Mantener vivo para debug
CMD ["tail", "-f", "/dev/null"]

# Puerto de app (tu stack usa 8000)
EXPOSE 8000
