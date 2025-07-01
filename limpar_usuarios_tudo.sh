#!/bin/bash
clear

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

spinner() {
    local pid=$!
    local spin='|/-\'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r${CYAN}${spin:$i:1}${RESET}"
        sleep 0.1
    done
    printf "\r"
}

echo -e "\n${RED}⚠️  ATENÇÃO: Este processo irá:${RESET}"
echo -e "${YELLOW}- Apagar todos os usuários criados (exceto root e nobody)"
echo "- Limpar senhas SSHPlus"
echo "- Zerar o arquivo /root/usuarios.db"
echo "- Apagar jobs do at"
echo "- Limpar arquivos de teste"
echo -e "- Remover todos os usuários de V2Ray e Xray (clientes do JSON)${RESET}"
echo

# Verifica se há backup existente
ULTIMO_BACKUP=$(ls -dt /root/backup_limpeza_* 2>/dev/null | head -n1)
if [ -d "$ULTIMO_BACKUP" ]; then
    echo -e "${YELLOW}📦 Backup encontrado: ${ULTIMO_BACKUP}${RESET}"
    read -p $'\033[1;33mDeseja restaurar este backup? (s/N): \033[0m' restaura
    if [[ "$restaura" == "s" || "$restaura" == "S" ]]; then
        echo -ne "${CYAN}🔄 Restaurando backup...${RESET} "
        (
            cp "$ULTIMO_BACKUP/passwd" /etc/passwd 2>/dev/null
            cp "$ULTIMO_BACKUP/shadow" /etc/shadow 2>/dev/null
            cp "$ULTIMO_BACKUP/group" /etc/group 2>/dev/null
            cp "$ULTIMO_BACKUP/gshadow" /etc/gshadow 2>/dev/null
            [ -f "$ULTIMO_BACKUP/usuarios.db" ] && cp "$ULTIMO_BACKUP/usuarios.db" /root/usuarios.db
            [ -d "$ULTIMO_BACKUP/senha" ] && cp -r "$ULTIMO_BACKUP/senha" /etc/SSHPlus/
            [ -f "$ULTIMO_BACKUP/v2ray_config.json" ] && cp "$ULTIMO_BACKUP/v2ray_config.json" /etc/v2ray/config.json
            [ -f "$ULTIMO_BACKUP/xray_config.json" ] && cp "$ULTIMO_BACKUP/xray_config.json" /usr/local/etc/xray/config.json
            [ -d "$ULTIMO_BACKUP/TesteAtlas" ] && cp -r "$ULTIMO_BACKUP/TesteAtlas" /etc/
            [ -d "$ULTIMO_BACKUP/atlasteste" ] && cp -r "$ULTIMO_BACKUP/atlasteste" /root/
        ) & spinner
        echo -e "${GREEN}✓ Backup restaurado com sucesso.${RESET}"
        exit 0
    fi
fi

read -p $'\033[1;31mDeseja continuar com a limpeza? (s/N): \033[0m' confirm
if [[ "$confirm" != "s" && "$confirm" != "S" ]]; then
    echo -e "${CYAN}❌ Operação cancelada.${RESET}"
    exit 1
fi

echo -e "${CYAN}⏳ Iniciando limpeza...${RESET}"

# Backup automático
echo -ne "${CYAN}🔹 Gerando backup de segurança...${RESET} "
(
    BACKUP_DIR="/root/backup_limpeza_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    cp /etc/passwd /etc/shadow /etc/group /etc/gshadow "$BACKUP_DIR"
    [ -f /root/usuarios.db ] && cp /root/usuarios.db "$BACKUP_DIR"
    [ -d /etc/SSHPlus/senha ] && cp -r /etc/SSHPlus/senha "$BACKUP_DIR/senha"
    [ -f /etc/v2ray/config.json ] && cp /etc/v2ray/config.json "$BACKUP_DIR/v2ray_config.json"
    [ -f /usr/local/etc/xray/config.json ] && cp /usr/local/etc/xray/config.json "$BACKUP_DIR/xray_config.json"
    [ -d /etc/TesteAtlas ] && cp -r /etc/TesteAtlas "$BACKUP_DIR/TesteAtlas"
    [ -d /root/atlasteste ] && cp -r /root/atlasteste "$BACKUP_DIR/atlasteste"
) & spinner
echo -e "${GREEN}✓${RESET}"

# Remover usuários
echo -ne "${CYAN}🔹 Removendo usuários do sistema...${RESET}\n"
total_users_removed=0
(
    while IFS=: read -r user _ uid _; do
        if [ "$uid" -ge 1000 ] && [ "$user" != "nobody" ] && [ "$user" != "root" ]; then
            userdel -r -f "$user" 2>/dev/null
            ((total_users_removed++))
        fi
    done < /etc/passwd
    echo "$total_users_removed" > /tmp/total_users_deleted
) & spinner
echo -e "${GREEN}✓${RESET}${CYAN}  Removidos:${RESET} ${YELLOW}$(cat /tmp/total_users_deleted)${RESET}"
rm -f /tmp/total_users_deleted

# SSHPlus
echo -ne "${CYAN}🔹 Limpando senhas SSHPlus...${RESET} "
(
    [ -d /etc/SSHPlus/senha ] && rm -rf /etc/SSHPlus/senha/*
) & spinner
echo -e "${GREEN}✓${RESET}"

# usuarios.db
echo -ne "${CYAN}🔹 Resetando /root/usuarios.db...${RESET} "
(
    [ -f /root/usuarios.db ] && > /root/usuarios.db
) & spinner
echo -e "${GREEN}✓${RESET}"

# Pastas de teste
echo -ne "${CYAN}🔹 Limpando pastas de teste...${RESET} "
(
    [ -d /etc/TesteAtlas ] && rm -rf /etc/TesteAtlas/*
    [ -d /root/atlasteste ] && rm -rf /root/atlasteste/*
) & spinner
echo -e "${GREEN}✓${RESET}"

# Jobs agendados
echo -ne "${CYAN}🔹 Cancelando jobs agendados (at)...${RESET} "
(
    if command -v atq >/dev/null; then
        for job in $(atq | awk '{print $1}'); do
            atrm "$job"
        done
    fi
) & spinner
echo -e "${GREEN}✓${RESET}"

# Limpar V2Ray/Xray
limpar_clients_json() {
    local arquivo=$1
    local tipo=$2
    local total_clientes=0

    if [ -f "$arquivo" ]; then
        if grep -q '"clients"' "$arquivo"; then
            if [ "$tipo" = "v2ray" ]; then
                total_clientes=$(jq '.inbounds[0].settings.clients | length' "$arquivo" 2>/dev/null)
                jq '(.inbounds[0].settings.clients) = []' "$arquivo" > "${arquivo}.tmp" && mv "${arquivo}.tmp" "$arquivo"
            elif [ "$tipo" = "xray" ]; then
                total_clientes=$(jq '[.inbounds[] | select(.tag == "inbound-sshplus").settings.clients[]] | length' "$arquivo" 2>/dev/null)
                jq '( .inbounds[] | select(.tag == "inbound-sshplus").settings.clients ) = []' "$arquivo" > "${arquivo}.tmp" && mv "${arquivo}.tmp" "$arquivo"
            fi
            chmod 777 "$arquivo"
            echo -e "${CYAN}🔹 Clientes removidos do $tipo: ${YELLOW}$total_clientes${RESET}"
        fi
    fi
}

limpar_clients_json "/etc/v2ray/config.json" "v2ray"
limpar_clients_json "/usr/local/etc/xray/config.json" "xray"

# Reiniciar serviços
echo -ne "${CYAN}🔹 Verificando e reiniciando serviços Xray/V2Ray...${RESET} "
(
    for serv in v2ray xray; do
        if [ -f "/etc/${serv}/config.json" ] || [ -f "/usr/local/etc/${serv}/config.json" ]; then
            systemctl restart "$serv" 2>/dev/null
        fi
    done
) & spinner
echo -e "${GREEN}✓${RESET}"

echo -e "${GREEN}✅ Limpeza completa!${RESET}"
