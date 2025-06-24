 Manejo por linea de comandos
python3 main.py registrar_usuario <nombre> <email> <password>
python3 main.py identificar_usuario <email> <password>
python3 main.py whoami
python3 main.py crear_red_privada <nombre>
python3 main.py ver_redes_privadas
python3 main.py ver_endpoints <id_red_privada>

python3 main.py conectar_endpoint <id_endpoint> <id_red_privada>
python3 main.py conectar_endpoint_directo <ip_wg_endpoint> <puerto_wg_endpoint>

python3 main.py obtener_clave_publica_servidor
python3 main.py obtener_configuracion_wireguard_local
python3 main.py obtener_configurarion_wireguard_servidor
python3 main.py añadir_ip_publica <ip>

python3 main.py consultar_ip_publica_cliente
python3 main.py registrar_como_peer <nombre> <id_red_privada> <ip_cliente> <puerto_cliente> 

python3 main.py obtener_clave_publica_cliente

python3 main.py init_wireguard_interfaz <ip_cliente>

python3 main.py crear_peer <public_key> <allowed_ips> <ip_cliente> <listen_port>

python3 main.py cerrar_sesion

 Nuevos casos

-- Cuando se quiere elegir el segmento de la VPN
python3 main.py crear_red_privada <nombre> <segmento_red>

-- Cuando se quiere borrar una red, un peer de una red
python3 main.py borrar_red_privada <id_red_privada>
python3 main.py borrar_red_peer <id_red_privada> <id_endpoint>


-- Cuando se quiere editar una red
     python3 main.py editar_red_privada <id_red_privada>
     Podria editar:
    - Segmento y mascara
    - Nombre
    - Allowed ips
    - Public key
    - Private key

-- Cuando se quiere editar una red segmento y mascara
    python3 main.py python3 main.py editar_red_privada <id_red_privada> <segmento_red> <mascara_red>

-- Cuando se quiere una red editar nombre
    python3 main.py editar_nombre_red_privada <id_red_privada> <ip_segment>

-- Cuando se quiere editar la lista de ips permitidas de una red

python3 main.py edit_allow_ips <id_red_privada> <list_allowed_ip>


-- Cuando se quiere editar un peer de una red
python3 main.py editar_red_peer <id_red_privada> <id_endpoint>
-- Podria editar:
    - Endpoint (IP publica)
    - Puerto
    - Nombre

-- Cuando se quiere editar el endpoint de peer
python3 main.py edit_endpoint <id_red_privada> <id_endpoint> <new_endpoint>

-- Cuando se quiere editar el puerto de un endpoint de peer
python3 main.py edit_endpoint_port <id_red_privada> <id_endpoint> <new_port>

-- Cuando se quiere editar el nombre de un endpoint
python3 main.py editar_endpoint_name <id_red_privada> <id_endpoint> <name>


