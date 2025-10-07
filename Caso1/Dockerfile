FROM almalinux:9

# Paquetes base + red + firewall + utilidades
RUN dnf -y update && \
    dnf -y install \
      iproute iputils net-tools \
      wireguard-tools \
      python3 python3-pip python3-scapy \
      nmap-ncat \
      openssh-clients \
      jq which procps-ng \
      iptables nftables conntrack-tools \
    && dnf clean all

# Que /usr/sbin y /sbin estén en PATH en shells no-login
ENV PATH="/usr/sbin:/sbin:${PATH}"

# Directorios de trabajo
RUN mkdir -p /shared/tests/artifacts /shared/Cliente

# Valores por defecto (overrideables)
ENV SERVER_IP=172.20.0.10 \
    SERVER_PORT=8080 \
    ALMA2_IP=172.20.0.11 \
    ALMA3_IP=172.20.0.12 \
    ALMA4_IP=172.20.0.13

# Mantener vivo para depurar
CMD ["tail", "-f", "/dev/null"]

# Puerto de la app del servidor
EXPOSE 8080