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
        sudo systemctl stop "$service" >/dev/null 2>&1
        sudo systemctl disable "$service" >/dev/null 2>&1
        log_message "Parado e desabilitado: $service"
    done
else
    log_message "Nenhum serviço encontrado começando com 'modulo'."
fi

services=$(systemctl list-units --type=service --no-legend 'ModuloSinc*.service' | awk '{print $1}')
if [ -n "$services" ]; then
    for service in $services; do
        sudo systemctl stop "$service" >/dev/null 2>&1
        sudo systemctl disable "$service" >/dev/null 2>&1
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

log_message "\n--- Criando servidor e compilando ModuloAtlas ---\n"
sudo mkdir -p /opt/apipainel/src >/dev/null 2>&1

if ! command -v cargo >/dev/null 2>&1; then
  log_message "Rust não encontrado, instalando com rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null 2>&1
  # Carrega o ambiente do rustup
  source "$HOME/.cargo/env"
  log_message "Rust e Cargo instalados com sucesso."
else
  log_message "Cargo já está instalado."
fi

cd /opt/apipainel/src
if [ ! -f Cargo.toml ]; then
  sudo cargo init --bin . >/dev/null 2>&1
fi

cat << 'EOF' | sudo tee Cargo.toml >/dev/null
[package]
name = "moduloatlas"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = "0.6"
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tower = "0.4"
tower-http = { version = "0.3", features = ["trace"] }
EOF

cat << EOF | sudo tee main.rs >/dev/null
use axum::{
    extract::ConnectInfo,
    routing::post,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json, Router,
};
use serde::Deserialize;
use std::{net::SocketAddr, process::Command, fs, io::Write};
use tokio::sync::Mutex;
use std::sync::Arc;

const SERVER_TOKEN: &str = "$server_token";
const IP_ACEITO: &str   = "$ipaceito";
const PORTA: u16        = $port;

const SERVER_LOG: &str      = "/opt/apipainel/server.log";
const BLOCKED_IPS_LOG: &str = "/opt/apipainel/blocked_ips.log";
const LOG_MAX_SIZE: u64     = 500 * 1024;

#[derive(Deserialize)]
struct ComandoPayload { comando: String }

fn rotate_log(path: &str) {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > LOG_MAX_SIZE {
            let _ = fs::remove_file(path);
        }
    }
}

fn log_message(msg: &str) {
    rotate_log(SERVER_LOG);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(SERVER_LOG) {
        let _ = writeln!(f, "{}", msg);
    }
}

fn log_blocked_ip(ip: &str) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(BLOCKED_IPS_LOG) {
        let _ = writeln!(f, "{}", ip);
    }
}

fn set_qos_priority() {
    let pid = std::process::id();
    let _ = Command::new("sudo").arg("renice").arg("-10").arg("-p").arg(pid.to_string()).output();
    let _ = Command::new("sudo").arg("ionice").arg("-c").arg("1").arg("-n").arg("0").arg("-p").arg(pid.to_string()).output();
    if let Ok(ifout) = Command::new("sh").arg("-c").arg("ip route | awk '/default/ {print $5}'").output() {
        if let Ok(iface) = String::from_utf8(ifout.stdout) {
            let iface = iface.trim();
            let tc = format!(
                "sudo tc qdisc del dev {iface} root; sudo tc qdisc add dev {iface} root handle 1: htb default 20;\
                 sudo tc class add dev {iface} parent 1: classid 1:10 htb rate 20mbit ceil 100mbit prio 1;\
                 sudo tc filter add dev {iface} protocol ip parent 1: prio 1 u32 match ip dport {port} 0xffff flowid 1:10",
                iface=iface, port=PORTA
            );
            let _ = Command::new("sh").arg("-c").arg(tc).output();
            log_message(&format!("🔹 QoS configurado para porta {} na interface {}", PORTA, iface));
        }
    }
}

async fn handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(p): Json<ComandoPayload>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();
    if ip != "127.0.0.1" && ip != IP_ACEITO {
        log_blocked_ip(&ip);
        return (StatusCode::FORBIDDEN, "IP não autorizado!").into_response();
    }
    let senha = headers.get("Senha").and_then(|v| v.to_str().ok()).unwrap_or("");
    if senha != SERVER_TOKEN {
        log_message("Tentativa de acesso não autorizada.");
        return (StatusCode::UNAUTHORIZED, "Não autorizado!").into_response();
    }
    log_message(&format!("Comando recebido: {}", p.comando));
    match Command::new("bash").arg("-c").arg(&p.comando).output() {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            log_message(&format!("Sucesso: {}", s));
            (StatusCode::OK, s.to_string()).into_response()
        }
        Ok(out) => {
            let e = String::from_utf8_lossy(&out.stderr);
            log_message(&format!("Erro: {}", e));
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
        Err(e) => {
            log_message(&format!("Exec falhou: {}", e));
            (StatusCode::INTERNAL_SERVER_ERROR, "Erro interno".to_string()).into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    rotate_log(SERVER_LOG);
    set_qos_priority();
    let addr = SocketAddr::from(([0, 0, 0, 0], PORTA));
    log_message(&format!("Servidor iniciado em http://{}", addr));
    println!("🚀 Servidor iniciado em http://{}", addr);
    let app = Router::new().route("/", post(handler));
    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
}
EOF

sudo cargo build --release >/dev/null 2>&1
sudo mv target/release/moduloatlas /opt/apipainel/ModuloAtlas

cd
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
cat << FIM > /opt/apipainel/Verificador.sh
#!/bin/bash

reativar_porta() {
    sudo tee /etc/systemd/system/ModuloAtlas.service >/dev/null << 'EOF_SERVICE'
[Unit]
Description=ModuloAtlas Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/apipainel/ModuloAtlas
WorkingDirectory=/opt/apipainel
StandardOutput=append:/opt/apipainel/instalacao.log
StandardError=append:/opt/apipainel/instalacao.log
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF_SERVICE

    # Recarrega o daemon, habilita e reinicia o serviço
    sudo systemctl daemon-reload >/dev/null 2>&1
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
        for tentativa in $(seq 1 $tentativas); do
            resposta=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:$port" -H "Senha: $server_token" -d "comando=teste")
            echo "Resposta HTTP: $resposta"
            if [[ "$resposta" -eq 200 ]]; then
                echo "A porta $port está ativa"
                return 0
            else
                echo "Porta $port inativa, tentando reativar... (tentativa $tentativa)"
                reativar_porta
            fi
        done
        echo "Falha ao reativar a porta $port após $tentativas tentativas."
    else
        echo "Senha de autenticação não encontrada"
    fi
}
sudo rm -rf /root/modulos.zip /opt/apipainel/src /root/modulosinstall.sh >/dev/null 2>&1
verifica_servidor
FIM

log_message "\n--- Ajustando permissões ---\n"
chmod -R 777 /opt/apipainel >/dev/null 2>&1
chmod 777 /etc/systemd/system/ModuloSinc.service >/dev/null 2>&1

# Reiniciar e habilitar o serviço
log_message "\n--- Reiniciando e habilitando serviço ---\n"
sudo systemctl daemon-reload >/dev/null 2>&1
sudo systemctl enable ModuloSinc.service >/dev/null 2>&1
sudo systemctl start ModuloSinc.service >/dev/null 2>&1
sudo systemctl restart ModuloSinc.service >/dev/null 2>&1

log_message "Serviço ModuloSinc.service reiniciado e habilitado com sucesso."

log_message "\n--- Aguardando e executando scripts adicionais ---\n"
sleep 1

log_message "\n--- Executando CorrecaoV2.py ---\n"
sudo python3 /opt/apipainel/CorrecaoV2.py >> $LOG_FILE 2>&1

log_message "\n--- Executando Verificador.sh ---\n"
sudo bash /opt/apipainel/Verificador.sh >> $LOG_FILE 2>&1

log_message "\n--- Limpando arquivos temporários ---\n"
sudo rm -rf "$ZIP_FILE" /root/modulosinstall.sh >/dev/null 2>&1

log_message "\n--- Instalação e configuração concluídas. ---\n"

echo "comandoenviadocomsucesso"
