#!/bin/bash
clear

# Define o diretório onde você quer excluir os arquivos
directory="/opt/apipainel"

# Exclui todos os arquivos no diretório, exceto "dominios.txt"
find "$directory" -type f ! -name 'dominios.txt' -exec rm -f {} + > /dev/null 2>&1

LOG_FILE="/opt/apipainel/instalacao.log"
DOMAINS_FILE="/opt/apipainel/dominios.txt"
ZIP_FILE="/root/modulos.zip"

# Função para registrar mensagens no log
log_message() {
    echo -e "$1" >> $LOG_FILE
}

# Criar diretório /opt/apipainel se não existir
[ ! -d /opt/apipainel ] && mkdir -p /opt/apipainel

# Verificar se o arquivo de log já existe e excluí-lo se existir
[ -f "$LOG_FILE" ] && rm "$LOG_FILE"

# Validar número de argumentos
if [ $# -ne 4 ]; then
    log_message "Uso: $0 <dominios> <porta> <servertoken> <ipaceito>"
    exit 1
fi

domains=$1
port=$2
server_token=$3
ipaceito=$4

update_hosts() {
  local hosts_file="/etc/hosts"

  if [[ -e "$hosts_file" ]]; then
    # Remove entradas anteriores para o(s) domínio(s)
    sed -i "/$domains/d" "$hosts_file" 2>/dev/null

  fi
}

update_debian_template() {
  local template="/etc/cloud/templates/hosts.debian.tmpl"

  if [[ -e "$template" ]]; then
    # Remove entradas anteriores para o(s) domínio(s)
    sed -i "/$domains/d" "$template" 2>/dev/null

  fi
}

# Chama as funções
update_hosts >/dev/null 2>&1
update_debian_template >/dev/null 2>&1

# Função para verificar se o comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

log_message "\n--- Iniciando o processo de instalação ---\n"

# Verificar se os comandos de firewall estão instalados
log_message "\n--- Verificando firewall e iptables ---\n"

# Verifica firewalld
if command_exists firewall-cmd; then
    log_message "firewalld já instalado."
else
    log_message "firewalld não encontrado."
fi

# Verifica iptables
if command_exists iptables && command_exists iptables-save; then
    log_message "iptables já instalado."
else
    log_message "iptables não encontrado."
fi

# Verifica ufw
if command_exists ufw; then
    log_message "ufw já instalado."
else
    log_message "ufw não encontrado."
fi

sudo fuser -k "$port"/tcp >/dev/null 2>&1

# Parar e desabilitar serviços existentes
log_message "\n--- Parando e desabilitando serviços existentes ---\n"
servicesm=$(systemctl list-units --type=service --no-legend 'modulo*.service' | awk '{print $1}')
if [ -n "$servicesm" ]; then
    for service in $servicesm; do
        systemctl stop "$service" >/dev/null 2>&1
        systemctl disable "$service" >/dev/null 2>&1
        log_message "Parado e desabilitado: $service"
    done
else
    log_message "Nenhum serviço encontrado começando com 'modulo'."
fi
services=$(systemctl list-units --type=service --no-legend 'ModuloSinc*.service' | awk '{print $1}')
if [ -n "$services" ]; then
    for service in $services; do
        systemctl stop "$service" >/dev/null 2>&1
        systemctl disable "$service" >/dev/null 2>&1
        log_message "Parado e desabilitado: $service"
    done
else
    log_message "Nenhum serviço encontrado começando com 'ModuloSinc'."
fi

# Salvar domínios no arquivo
log_message "\n--- Salvando domínios no arquivo ---\n"
for domain in $(echo $domains | tr "," "\n"); do
    if ! grep -qx "$domain" "$DOMAINS_FILE"; then
        echo "$domain" >> "$DOMAINS_FILE"
        log_message "Dominio adicionado: $domain"
    else
        log_message "Dominio já existe: $domain"
    fi
done

# Configurar firewall em silêncio
log_message "\n--- Configurando firewall para a porta $port ---\n"
if command_exists firewall-cmd; then
    sudo firewall-cmd --zone=public --add-port=$port/tcp --permanent >/dev/null 2>&1
    sudo firewall-cmd --reload >/dev/null 2>&1
fi

if command_exists iptables; then
    sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT >/dev/null 2>&1
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null 2>&1
fi

if command_exists ufw; then
    sudo ufw allow $port/tcp >/dev/null 2>&1
fi

# Descompactar o arquivo ZIP
log_message "\n--- Descompactando módulos ---\n"
if [ -f "$ZIP_FILE" ]; then
    unzip -o "$ZIP_FILE" -d /opt/apipainel/ >/dev/null 2>&1
    find /opt/apipainel -type f -exec dos2unix {} + >/dev/null 2>&1
    log_message "Módulos descompactados com sucesso."
else
    log_message "Arquivo $ZIP_FILE não encontrado. Abortando."
    exit 1
fi

# Criar módulo Python em silêncio
log_message "\n--- Criando módulo Python ---\n"
cat << EOF > /opt/apipainel/ModuloSinc.py
# -*- coding: utf-8 -*-

from http.server import BaseHTTPRequestHandler, HTTPServer
import cgi
import subprocess
import logging
import os

# Configurações
senha_autenticacao = '$server_token'
allowed_ips = ['127.0.0.1', '$ipaceito']

# Arquivos de log separados
server_log_file = os.path.join(os.path.dirname(__file__), 'server.log')
blocked_ips_log_file = os.path.join(os.path.dirname(__file__), 'blocked_ips.log')
log_max_size = 500 * 1024  # 500 KB

def setup_logging():
    """Configura logging rotativo para logs do servidor e logs de IP bloqueados."""
    # Rotação do log do servidor
    if os.path.exists(server_log_file) and os.path.getsize(server_log_file) > log_max_size:
        os.remove(server_log_file)  # Apaga e recria

    logging.basicConfig(
        filename=server_log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def log_message(message):
    """Grava mensagens no log principal (server.log)."""
    logging.info(message)

def log_blocked_ip(ip):
    """Grava IPs bloqueados no log separado (blocked_ips.log)."""
    with open(blocked_ips_log_file, "a") as ip_log:
        ip_log.write(f"{ip}\n")

setup_logging()

def set_qos_priority():
    """Configura QoS para garantir 20% da banda ao servidor e liberar 80% para outros processos."""
    try:
        # Obtém o PID do processo atual
        pid = os.getpid()

        # Ajusta prioridade do processo na CPU e disco
        subprocess.run(f"sudo renice -n -10 -p {pid}", shell=True)  # Prioridade alta na CPU
        subprocess.run(f"sudo ionice -c 1 -n 0 -p {pid}", shell=True)  # Prioridade máxima no disco

        # Configura Traffic Control para reservar 20% da banda para o servidor
        server_port = "$port"  # Substituir pela porta real do servidor

        # Obtém a interface de rede principal
        primary_interface = subprocess.check_output(
            "ip route | grep default | awk '{print $5}'", shell=True
        ).decode().strip()

        # Remove regras antigas (se existirem)
        subprocess.run(f"sudo tc qdisc del dev {primary_interface} root", shell=True, stderr=subprocess.DEVNULL)

        # Define nova política de controle de tráfego
        subprocess.run(f"""
        sudo tc qdisc add dev {primary_interface} root handle 1: htb default 20
        sudo tc class add dev {primary_interface} parent 1: classid 1:1 htb rate 100mbit ceil 100mbit
        sudo tc class add dev {primary_interface} parent 1: classid 1:10 htb rate 20mbit ceil 100mbit prio 1
        sudo tc class add dev {primary_interface} parent 1: classid 1:20 htb rate 80mbit ceil 100mbit prio 2
        sudo tc filter add dev {primary_interface} protocol ip parent 1: prio 1 u32 match ip dport {server_port} 0xffff flowid 1:10
        sudo tc filter add dev {primary_interface} protocol ip parent 1: prio 1 u32 match ip sport {server_port} 0xffff flowid 1:10
        """, shell=True)

        log_message(f"🔹 QoS configurado: Servidor Python tem 20% da banda reservada e outros processos podem usar os 80% restantes.")

    except Exception as e:
        log_message(f"Erro ao configurar QoS: {e}")

# Aplica as regras de prioridade de rede
set_qos_priority()

class MyRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        client_ip = self.client_address[0]

        # Bloqueia IPs não autorizados
        if client_ip not in allowed_ips:
            self.send_response(403)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write('IP não autorizado!'.encode())
            log_blocked_ip(client_ip)  # Registra no log de IPs bloqueados
            return

        # Verifica autenticação
        if 'Senha' in self.headers and self.headers['Senha'] == senha_autenticacao:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            command = form.getvalue('comando')

            try:
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                log_message(f"Comando executado: {command}")
            except subprocess.CalledProcessError as e:
                result = e.output
                log_message(f"Erro ao executar comando: {command}")

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(result)
        else:
            self.send_response(401)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write('Não autorizado!'.encode())
            log_message("Tentativa de acesso não autorizada.")

host = '0.0.0.0'
port = $port

server = HTTPServer((host, port), MyRequestHandler)

log_message(f'Servidor iniciado em {host}:{port}')
server.serve_forever()
EOF

log_message "\n--- Criando serviço systemd ---\n"
cat << EOF > /etc/systemd/system/ModuloSinc.service
[Unit]
Description=Modulo Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /opt/apipainel/ModuloSinc.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

log_message "\n--- Criando script de inicialização ---\n"
cat << EOF > /opt/apipainel/ModuloSinc.sh
#!/bin/bash

domains_file="/opt/apipainel/dominios.txt"

start_loop() {
    local domain=\$1
    while true; do
        curl -s --ipv4 -X POST \\
          -H "Host: \$domain" \\
          -d "servertoken=$server_token" \\
          "http://$ipaceito/crons.php" > /dev/null
        sleep 3
    done
}

while IFS= read -r domain; do
    if [[ -n "\$domain" ]]; then
        start_loop "\$domain" &
    fi
done < "\$domains_file"

wait
EOF

log_message "\n--- Criando script Verificador ---\n"
cat << EOF > /opt/apipainel/Verificador.sh
#!/bin/bash

reativar_porta() {
    sudo bash -c 'cat <<SERVICO > /etc/systemd/system/ModuloAtlas.service
[Unit]
Description=ModuloAtlas Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/apipainel/ModuloSinc.py
WorkingDirectory=/opt/apipainel
StandardOutput=append:/opt/apipainel/instalacao.log
StandardError=append:/opt/apipainel/instalacao.log
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICO'

    sudo systemctl daemon-reexec
    sudo systemctl daemon-reload
    sudo systemctl enable ModuloAtlas.service >/dev/null 2>&1
    sudo systemctl restart ModuloAtlas.service >/dev/null 2>&1
    sleep 5
}

verifica_cron() {
    if crontab -l | grep -q 'Verificador.sh'; then
        echo 'Cron ativo'
        return 0
    fi
    echo 'Cron inativo'
    return 1
}

limpar_crontab() {
    crontab -l | grep -v '^.*Verificador.*$' | crontab -
}

ativar_cron() {
    (crontab -l ; echo "*/30 * * * * bash /opt/apipainel/Verificador.sh"; echo "@reboot bash /opt/apipainel/Verificador.sh") | crontab -
    sudo systemctl restart cron
}

verificar_crontab() {
    if ! verifica_cron; then
        echo 'Cron inativo, ativando...'
        ativar_cron
    fi
}

limpar_crontab
verificar_crontab

verifica_servidor() {
    local tentativas=5

    if [[ -n "$server_token" ]]; then
        for tentativa in \$(seq 1 \$tentativas); do
            resposta=\$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:$port" -H "Senha: $server_token" -d "comando=teste")
            echo "Resposta HTTP: \$resposta"
            if [[ "\$resposta" -eq 200 ]]; then
                echo "A porta \$port está ativa"
                return 0
            else
                echo "Porta $port inativa, tentando reativar... (tentativa \$tentativa)"
                reativar_porta
            fi
        done
        echo "Falha ao reativar a porta $port após \$tentativas tentativas."
    else
        echo "Senha de autenticação não encontrada"
    fi
}

verifica_servidor
EOF

log_message "\n--- Ajustando permissões ---\n"
chmod -R 777 /opt/apipainel >/dev/null 2>&1
chmod 777 /etc/systemd/system/ModuloSinc.service >/dev/null 2>&1

# Reiniciar e habilitar o serviço
log_message "\n--- Reiniciando e habilitando serviço ---\n"
systemctl daemon-reload >/dev/null 2>&1
systemctl enable ModuloSinc.service >/dev/null 2>&1
systemctl start ModuloSinc.service >/dev/null 2>&1
systemctl restart ModuloSinc.service >/dev/null 2>&1

log_message "Serviço ModuloSinc.service reiniciado e habilitado com sucesso."

log_message "\n--- Aguardando e executando scripts adicionais ---\n"
sleep 1

log_message "\n--- Executando CorrecaoV2.py ---\n"
sudo python3 /opt/apipainel/CorrecaoV2.py >> $LOG_FILE 2>&1

log_message "\n--- Executando Verificador.sh ---\n"
sudo bash /opt/apipainel/Verificador.sh >> $LOG_FILE 2>&1

log_message "\n--- Limpando arquivos temporários ---\n"
rm $ZIP_FILE modulosinstall.sh >/dev/null 2>&1

log_message "\n--- Instalação e configuração concluídas. ---\n"

echo "comandoenviadocomsucesso"
