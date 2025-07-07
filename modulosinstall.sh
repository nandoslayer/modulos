#!/bin/bash

directory="/opt/apipainel"

# Define cores para saída (opcional)
green="\033[1;32m"
yellow="\033[1;33m"
red="\033[1;31m"
reset="\033[0m"

LOG_FILE="/opt/apipainel/instalacao.log"
DOMAINS_FILE="/opt/apipainel/dominios.txt"
ZIP_FILE="/root/modulos.zip"

[ ! -d /opt/apipainel ] && mkdir -p /opt/apipainel

# Função para registrar mensagens no log
log_message() {
    echo -e "$1" >> "$LOG_FILE"
}

# Função para registrar cabeçalhos bonitos
log_header() {
    log_message "\n==============================================================="
    log_message " $1"
    log_message "==============================================================="
}

# Função para logar sucesso/erro
log_status() {
    if [ "$1" -eq 0 ]; then
        log_message "✅ $2"
    else
        log_message "❌ $3"
    fi
}

log_header "INÍCIO DA INSTALAÇÃO - $(date '+%d/%m/%Y %H:%M:%S')"

# Limpa o log anterior e arquivos do diretório (exceto dominios.txt)
[ -f "$LOG_FILE" ] && rm "$LOG_FILE"
find "$directory" -type f ! -name 'dominios.txt' -exec rm -f {} + > /dev/null 2>&1

# Finaliza ModuloSinc
log_header "Finalizando processos ModuloSinc existentes"
pids=$(ps aux | grep '[M]oduloSinc' | awk '{print $2}' | grep -E '^[0-9]+$')
if [ -n "$pids" ]; then
    for pid in $pids; do
        if [[ "$pid" =~ ^[0-9]+$ ]]; then
            kill -9 "$pid" >/dev/null 2>&1
            log_message "🔸 Processo ModuloSinc encerrado (PID: $pid)"
        fi
    done
else
    log_message "🔸 Nenhum processo ModuloSinc em execução."
fi

# Fecha sockets TCP/UDP do ModuloSinc
socket_pids=$(lsof -nP -iUDP -iTCP 2>/dev/null | grep ModuloSinc | awk '{print $2}' | sort -u | grep -E '^[0-9]+$')
if [ -n "$socket_pids" ]; then
    for pid in $socket_pids; do
        if [[ "$pid" =~ ^[0-9]+$ ]]; then
            kill -9 "$pid" >/dev/null 2>&1
            log_message "🔸 Socket encerrado para ModuloSinc (PID: $pid)"
        fi
    done
fi

# Verifica argumentos
if [ $# -ne 4 ]; then
    log_message "❌ Uso: $0 <dominios> <porta> <servertoken> <ipaceito>"
    exit 1
fi

domains=$1
port=$2
server_token=$3
ipaceito=$4

# Remove domínios antigos do hosts
log_header "Atualizando arquivos de hosts"
sed -i "/$domains/d" /etc/hosts 2>/dev/null
sed -i "/$domains/d" /etc/cloud/templates/hosts.debian.tmpl 2>/dev/null

# Função para verificar se o comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

log_header "Verificando firewall e dependências"

# Firewall
for fw in firewalld iptables ufw; do
    if command_exists "$fw"; then
        log_message "✅ $fw instalado."
    else
        log_message "❌ $fw não encontrado."
    fi
done

log_header "Verificando e instalando dependências do sistema"
sudo apt update -qq > /dev/null 2>&1

deps_bin=(python3 python3-pip python3-venv python3-distutils curl unzip wget git dos2unix zip tar nano lsof net-tools sudo cron jq bc)

for dep in "${deps_bin[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        log_message "Instalando $dep ..."
        sudo apt-get install -y -qq --reinstall "$dep" > /dev/null 2>&1
        log_status $? "$dep instalado!" "Falha ao instalar $dep."
    else
        log_message "✅ $dep já instalado."
    fi
done

log_header "Parando e desabilitando serviços antigos"
for padrao in 'modulo*.service' 'ModuloSinc*.service' 'ModuloCron*.service'; do
    services=$(systemctl list-units --type=service --no-legend "$padrao" 2>/dev/null | awk '{print $1}' | grep -v -e '^$' -e '^unknown$' -e '^UNIT$')
    if [ -n "$services" ]; then
        for service in $services; do
            if [[ -n "$service" && "$service" != "unknown" ]]; then
                systemctl stop "$service" >/dev/null 2>&1
                systemctl disable "$service" >/dev/null 2>&1
                log_message "🔸 Parado e desabilitado: $service"
            fi
        done
    else
        log_message "🔸 Nenhum serviço encontrado com padrão $padrao."
    fi
done

log_header "Salvando domínios no arquivo"
for domain in $(echo $domains | tr "," "\n"); do
    if ! grep -qx "$domain" "$DOMAINS_FILE"; then
        echo "$domain" >> "$DOMAINS_FILE"
        log_message "🌐 Domínio adicionado: $domain"
    else
        log_message "🌐 Domínio já existe: $domain"
    fi
done

log_header "Configurando firewall para a porta $port (TCP/UDP)"
if command_exists firewall-cmd; then
    sudo firewall-cmd --zone=public --add-port=${port}/tcp --permanent >/dev/null 2>&1
    sudo firewall-cmd --zone=public --add-port=${port}/udp --permanent >/dev/null 2>&1
    sudo firewall-cmd --reload >/dev/null 2>&1
    log_status $? "firewalld atualizado!" "Falha no firewalld."
fi

if command_exists iptables; then
    sudo iptables -D INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1
    sudo iptables -D INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
    sudo iptables -A INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1
    sudo iptables -A INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null 2>&1
    if systemctl list-units --type=service | grep -qw netfilter-persistent; then
        sudo systemctl reload netfilter-persistent >/dev/null 2>&1
    fi
    log_status $? "iptables atualizado!" "Falha ao atualizar iptables."
fi

if command_exists ufw; then
    sudo ufw allow $port/tcp >/dev/null 2>&1
    sudo ufw allow $port/udp >/dev/null 2>&1
    sudo ufw reload >/dev/null 2>&1
    log_status $? "ufw atualizado!" "Falha ao atualizar ufw."
fi

log_header "Descompactando módulos"
if [ -f "$ZIP_FILE" ]; then
    unzip -o "$ZIP_FILE" -d /opt/apipainel/ >/dev/null 2>&1
    log_status $? "Módulos descompactados com sucesso." "Erro ao descompactar módulos."
else
    log_message "❌ Arquivo $ZIP_FILE não encontrado. Abortando."
    exit 1
fi

echo '{"comandos_proibidos": ["rm", "dd", "mkfs", "poweroff", "init", "reboot", "shutdown", "useradd", "passwd", "chpasswd", "usermod", "adduser", "groupadd", "chown", "chmod", "perl", "php", "systemctl", "visudo", "scp", "nc", "ncat", "socat"]}' > /opt/apipainel/comandos_bloqueados.json
echo '{"ips": ["127.0.0.1", "'$ipaceito'"]}' > /opt/apipainel/ips_autorizados.json

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

log_header "Aplicando dos2unix em todos os arquivos"
if command_exists dos2unix; then
    find /opt/apipainel -type f -exec dos2unix {} \; >/dev/null 2>&1
    log_status $? "Conversão dos2unix aplicada com sucesso." "Erro: dos2unix não está instalado."
else
    log_message "Erro: dos2unix não está instalado."
fi

log_header "Ajustando permissões"
chmod -R 777 /opt/apipainel >/dev/null 2>&1
chmod 777 /etc/systemd/system/ModuloSinc.service /etc/systemd/system/ModuloCron.service >/dev/null 2>&1

log_header "Reiniciando e habilitando serviços"
systemctl daemon-reload >/dev/null 2>&1
systemctl enable ModuloSinc.service >/dev/null 2>&1
systemctl start ModuloSinc.service >/dev/null 2>&1
systemctl restart ModuloSinc.service >/dev/null 2>&1
systemctl enable ModuloCron.service >/dev/null 2>&1
systemctl start ModuloCron.service >/dev/null 2>&1
systemctl restart ModuloCron.service >/dev/null 2>&1
log_message "✅ Serviço ModuloSinc.service e ModuloCron.service reiniciados e habilitados com sucesso."

log_header "Executando scripts adicionais"
sleep 1
log_message "Executando CorrecaoV2"
sudo python3 /opt/apipainel/CorrecaoV2.py >> $LOG_FILE 2>&1

log_header "Limpando arquivos temporários"
rm $ZIP_FILE modulosinstall.sh >/dev/null 2>&1

log_header "INSTALAÇÃO E CONFIGURAÇÃO CONCLUÍDAS"
echo "comandoenviadocomsucesso"