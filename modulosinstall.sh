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

# Finaliza qualquer instância ativa do ModuloSinc.py
log_message "\n--- Finalizando processos ModuloSinc existentes (UDP/TCP) ---\n"

# Mata qualquer processo com nome ModuloSinc (com ou sem .py)
pids=$(ps aux | grep '[M]oduloSinc' | awk '{print $2}')
if [ -n "$pids" ]; then
    for pid in $pids; do
        kill -9 "$pid" >/dev/null 2>&1
        log_message "Processo ModuloSinc encerrado (PID: $pid)"
    done
else
    log_message "Nenhum processo ModuloSinc em execução."
fi

# Fecha sockets TCP/UDP explicitamente (caso o python fique travado em algum socket)
for pid in $(lsof -nP -iUDP -iTCP | grep ModuloSinc | awk '{print $2}' | sort -u); do
    kill -9 "$pid" >/dev/null 2>&1
    log_message "Socket encerrado para ModuloSinc (PID: $pid)"
done

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

log_message "\n--- Verificando dependências obrigatórias ---\n"
for dep in python3 curl unzip dos2unix; do
    if ! command_exists $dep; then
        log_message "Dependência ausente: $dep. Instalando..."
        apt-get install -y $dep >/dev/null 2>&1
        if command_exists $dep; then
            log_message "$dep instalado com sucesso."
        else
            log_message "Erro ao instalar $dep."
            exit 1
        fi
    else
        log_message "$dep já instalado."
    fi
done

log_message "\n--- Verificando e instalando dependências do sistema ---\n"

sudo apt update -qq > /dev/null

# Se for Ubuntu e não tem deadsnakes, adiciona o PPA
if grep -qi "ubuntu" /etc/os-release; then
    if ! grep -q "deadsnakes" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
        log_message "Adicionando repositório deadsnakes (python3.8) no Ubuntu..."
        sudo apt-get install -y -qq software-properties-common > /dev/null
        sudo add-apt-repository -y ppa:deadsnakes/ppa > /dev/null
        sudo apt update -qq > /dev/null
    else
        log_message "Repositório deadsnakes já adicionado."
    fi
fi

packages_to_install=(
    software-properties-common
    curl language-pack-en bc nethogs screen nano unzip lsof net-tools dos2unix
    nload pkg-config jq figlet python3 python3-pip python python-pip build-essential
    libssl-dev libffi-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev
    wget git ca-certificates
    python3.8 python3.8-dev python3.8-venv libpython3.8
)

for pkg in "${packages_to_install[@]}"; do
    log_message "Instalando/reinstalando $pkg ..."
    sudo apt-get install -y -qq --reinstall "$pkg" > /dev/null
done

log_message "Dependências e libs principais instaladas!"

# Testa se a dependência ficou instalada
if [ ! -f /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0 ] && [ ! -f /usr/lib/aarch64-linux-gnu/libpython3.8.so.1.0 ]; then
    log_message "ERRO: Não foi possível instalar a libpython3.8. O ModuloSinc pode não funcionar!"
fi

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
services=$(systemctl list-units --type=service --no-legend 'ModuloSinc*.service' 'ModuloCron*.service' | awk '{print $1}')
if [ -n "$services" ]; then
    for service in $services; do
        systemctl stop "$service" >/dev/null 2>&1
        systemctl disable "$service" >/dev/null 2>&1
        log_message "Parado e desabilitado: $service"
    done
else
    log_message "Nenhum serviço encontrado começando com 'ModuloSinc' ou 'ModuloCron'."
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

log_message "\n--- Configurando firewall para a porta $port (TCP/UDP) ---\n"
if command_exists firewall-cmd; then
    sudo firewall-cmd --zone=public --add-port=${port}/tcp --permanent >/dev/null 2>&1
    sudo firewall-cmd --zone=public --add-port=${port}/udp --permanent >/dev/null 2>&1
    sudo firewall-cmd --reload >/dev/null 2>&1
fi

if command_exists iptables; then
    # Remove todas as regras para a porta (TCP)
    while sudo iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; do
        sudo iptables -D INPUT -p tcp --dport $port -j ACCEPT >/dev/null 2>&1
    done
    # Remove todas as regras para a porta (UDP)
    while sudo iptables -C INPUT -p udp --dport $port -j ACCEPT 2>/dev/null; do
        sudo iptables -D INPUT -p udp --dport $port -j ACCEPT >/dev/null 2>&1
    done

    # Agora adiciona só uma vez (TCP e UDP)
    sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT >/dev/null 2>&1
    sudo iptables -A INPUT -p udp --dport $port -j ACCEPT >/dev/null 2>&1
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null 2>&1
fi

if command_exists ufw; then
    sudo ufw allow $port/tcp >/dev/null 2>&1
    sudo ufw allow $port/udp >/dev/null 2>&1
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

echo '{"comandos_proibidos": ["rm", "dd", "mkfs", "poweroff", "init", "reboot", "shutdown", "useradd", "passwd", "chpasswd", "usermod", "adduser", "groupadd", "chown", "chmod", "perl", "php", "systemctl", "visudo", "scp", "nc", "ncat", "socat"]}' > /opt/apipainel/comandos_bloqueados.json
echo '{"ips": ["127.0.0.1", "'$ipaceito'"]}' > /opt/apipainel/ips_autorizados.json

DESTINO="/opt/apipainel/ModuloSinc"
URL_X64="https://github.com/nandoslayer/modulos/raw/refs/heads/main/ModuloSinc64"
URL_ARM64="https://github.com/nandoslayer/modulos/raw/refs/heads/main/ModuloSincArm64"

ARQUITETURA="$(uname -m)"

if [ "$ARQUITETURA" = "x86_64" ]; then
    log_message "\nArquitetura x86_64 detectada. Baixando ModuloSinc64..."
    wget -q --no-check-certificate -O "$DESTINO" "$URL_X64"
    log_message "Arquivo ModuloSinc64 salvo como $DESTINO"
elif [ "$ARQUITETURA" = "aarch64" ] || [ "$ARQUITETURA" = "arm64" ]; then
    log_message "\nArquitetura ARM64 detectada. Baixando ModuloSincArm64..."
    wget -q --no-check-certificate -O "$DESTINO" "$URL_ARM64"
    log_message "Arquivo ModuloSincArm64 salvo como $DESTINO"
else
    log_message "Arquitetura $ARQUITETURA não suportada para esse módulo."
    exit 1
fi

cat << EOF > /etc/systemd/system/ModuloSinc.service
[Unit]
Description=ModuloSinc UDP Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/apipainel/ModuloSinc $server_token $port
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/ModuloCron.service
[Unit]
Description=Modulo Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /opt/apipainel/ModuloCron.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /opt/apipainel/ModuloCron.sh
#!/bin/bash

DOMS="/opt/apipainel/dominios.txt"
while read -r domain; do
  while true; do
    curl -s --ipv4 -X POST \
      -H "Host: \$domain" \
      -d "servertoken=$server_token" \
      "http://$ipaceito/crons.php" > /dev/null
    sleep 3
  done &
done < \$DOMS
wait
EOF

log_message "\n--- Aplicando dos2unix em todos os arquivos ---\n"
if command_exists dos2unix; then
    find /opt/apipainel -type f -exec dos2unix {} \; >/dev/null 2>&1
    log_message "Conversão dos2unix aplicada com sucesso."
else
    log_message "Erro: dos2unix não está instalado."
fi

log_message "\n--- Ajustando permissões ---\n"
chmod -R 777 /opt/apipainel >/dev/null 2>&1
chmod 777 /etc/systemd/system/ModuloSinc.service /etc/systemd/system/ModuloCron.service >/dev/null 2>&1

log_message "\n--- Reiniciando e habilitando serviço ---\n"
systemctl daemon-reload >/dev/null 2>&1
systemctl enable ModuloSinc.service >/dev/null 2>&1
systemctl start ModuloSinc.service >/dev/null 2>&1
systemctl restart ModuloSinc.service >/dev/null 2>&1
systemctl enable ModuloCron.service >/dev/null 2>&1
systemctl start ModuloCron.service >/dev/null 2>&1
systemctl restart ModuloCron.service >/dev/null 2>&1
log_message "Serviço ModuloSinc.service reiniciado e habilitado com sucesso."

log_message "\n--- Aguardando e executando scripts adicionais ---\n"
sleep 1

log_message "\n--- Executando CorrecaoV2 ---\n"
sudo python3 /opt/apipainel/CorrecaoV2.py >> $LOG_FILE 2>&1

log_message "\n--- Limpando arquivos temporários ---\n"
rm $ZIP_FILE modulosinstall.sh >/dev/null 2>&1

log_message "\n--- Instalação e configuração concluídas. ---\n"
echo "comandoenviadocomsucesso"
