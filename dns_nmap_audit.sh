#!/bin/bash
# ==============================================================================
# LABS 3 - 2311: Herramienta de Reconocimiento DNS y Evaluación Nmap + NSE
# Descripción:
#   Script interactivo en Bash con menú (while true + case) que permite:
#   1) Obtener información DNS de un dominio (A, AAAA, MX, NS, TXT, SOA, AXFR)
#      para identificar máquinas con posibles datos sensibles.
#   2) Lanzar un submenú de Nmap sobre la máquina seleccionada para determinar:
#      - Estado de la máquina (host activo/inactivo)
#      - Puertos abiertos y servicios/versiones en ejecución
#      - Evaluación con los scripts NSE correspondientes al servicio y puerto
# ==============================================================================

# Colores para mejorar la lectura en terminal
VERDE='\033[0;32m'
AMARILLO='\033[1;33m'
AZUL='\033[0;34m'
CYAN='\033[0;36m'
ROJO='\033[0;31m'
NC='\033[0m' # Sin color

# Variables globales
DOMINIO=""
DIR_RESULTADOS="./resultados"
IPS_DETECTADAS=()

# Comprobación de herramientas necesarias
comprobar_dependencias() {
    for herramienta in dig nmap; do
        if ! command -v "$herramienta" >/dev/null 2>&1; then
            echo -e "${ROJO}[!] Error: '$herramienta' no está instalado. Instálalo con: sudo apt install dnsutils nmap${NC}"
            exit 1
        fi
    done
    mkdir -p "$DIR_RESULTADOS"
}

# Registrar IPs únicas encontradas durante el reconocimiento DNS
agregar_ip() {
    local ip="$1"
    local origen="$2"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local entrada="${ip} (${origen})"
        for existente in "${IPS_DETECTADAS[@]}"; do
            if [[ "$existente" == "$entrada" ]]; then
                return
            fi
        done
        IPS_DETECTADAS+=("$entrada")
    fi
}

# Solicitar dominio al usuario
pedir_dominio() {
    echo -e "${CYAN}------------------------------------------------------------${NC}"
    echo -e "${VERDE}Bienvenid@ a la herramienta de consulta DNS y auditoría Nmap/NSE.${NC}"
    echo -e "Ejemplo de dominio a introducir ---> ${AMARILLO}scanme.nmap.org${NC} o ${AMARILLO}google.es${NC}"
    echo -e "${CYAN}------------------------------------------------------------${NC}"
    read -p "Escribe el dominio objetivo: " DOMINIO
    if [[ -z "$DOMINIO" ]]; then
        echo -e "${ROJO}[!] El dominio no puede estar vacío.${NC}"
        pedir_dominio
    fi
    IPS_DETECTADAS=()
}

# ==============================================================================
# FASE 1: FUNCIONES DE CONSULTA DNS
# ==============================================================================

consulta_ip() {
    echo -e "\n${AZUL}[*] Obteniendo registros A (IPv4) y AAAA (IPv6) para $DOMINIO...${NC}"
    local ips_a
    ips_a=$(dig +short "$DOMINIO" A)
    local ips_aaaa
    ips_aaaa=$(dig +short "$DOMINIO" AAAA)

    echo -e "${VERDE}Direcciones IPv4 (Registro A):${NC}"
    if [[ -n "$ips_a" ]]; then
        echo "$ips_a"
        while IFS= read -r ip; do
            agregar_ip "$ip" "Registro A - $DOMINIO"
        done <<< "$ips_a"
    else
        echo "  (Sin registros A)"
    fi

    echo -e "${VERDE}Direcciones IPv6 (Registro AAAA):${NC}"
    if [[ -n "$ips_aaaa" ]]; then
        echo "$ips_aaaa"
    else
        echo "  (Sin registros AAAA)"
    fi
}

consulta_mx() {
    echo -e "\n${AZUL}[*] Obteniendo servidores de correo (Registro MX - datos sensibles) para $DOMINIO...${NC}"
    local mx_res
    mx_res=$(dig +short "$DOMINIO" MX)
    if [[ -n "$mx_res" ]]; then
        echo -e "${VERDE}Servidores de correo encontrados:${NC}"
        echo "$mx_res"
        while IFS= read -r linea; do
            local host_mx
            host_mx=$(echo "$linea" | awk '{print $2}' | sed 's/\.$//')
            if [[ -n "$host_mx" ]]; then
                local ip_mx
                ip_mx=$(dig +short "$host_mx" A | head -n 1)
                if [[ -n "$ip_mx" ]]; then
                    echo -e "  -> ${AMARILLO}$host_mx${NC} => $ip_mx"
                    agregar_ip "$ip_mx" "MX: $host_mx"
                fi
            fi
        done <<< "$mx_res"
    else
        echo "  (Sin registros MX)"
    fi
}

consulta_ns() {
    echo -e "\n${AZUL}[*] Obteniendo servidores de nombres (Registro NS) para $DOMINIO...${NC}"
    local ns_res
    ns_res=$(dig +short "$DOMINIO" NS)
    if [[ -n "$ns_res" ]]; then
        echo -e "${VERDE}Servidores DNS autoritativos:${NC}"
        echo "$ns_res"
        while IFS= read -r ns; do
            local host_ns
            host_ns=$(echo "$ns" | sed 's/\.$//')
            if [[ -n "$host_ns" ]]; then
                local ip_ns
                ip_ns=$(dig +short "$host_ns" A | head -n 1)
                if [[ -n "$ip_ns" ]]; then
                    echo -e "  -> ${AMARILLO}$host_ns${NC} => $ip_ns"
                    agregar_ip "$ip_ns" "NS: $host_ns"
                fi
            fi
        done <<< "$ns_res"
    else
        echo "  (Sin registros NS)"
    fi
}

consulta_txt_soa() {
    echo -e "\n${AZUL}[*] Obteniendo registros TXT (SPF/DMARC/verificaciones) y SOA para $DOMINIO...${NC}"
    echo -e "${VERDE}Registros TXT:${NC}"
    local txt_res
    txt_res=$(dig +short "$DOMINIO" TXT)
    if [[ -n "$txt_res" ]]; then
        echo "$txt_res"
    else
        echo "  (Sin registros TXT)"
    fi

    echo -e "\n${VERDE}Registro SOA (Autoridad de zona):${NC}"
    local soa_res
    soa_res=$(dig +short "$DOMINIO" SOA)
    if [[ -n "$soa_res" ]]; then
        echo "$soa_res"
    else
        echo "  (Sin registro SOA)"
    fi
}

consulta_dns_completa() {
    local archivo_dns="${DIR_RESULTADOS}/dns_${DOMINIO}.txt"
    echo -e "\n${CYAN}=== RECONOCIMIENTO DNS COMPLETO PARA: $DOMINIO ===${NC}"
    {
        echo "=== RECONOCIMIENTO DNS: $DOMINIO ($(date)) ==="
        consulta_ip
        consulta_mx
        consulta_ns
        consulta_txt_soa
    } | tee "$archivo_dns"

    # Recargamos las IPs en el array porque el pipe ejecuta en subshell
    while IFS= read -r ip; do agregar_ip "$ip" "Registro A - $DOMINIO"; done < <(dig +short "$DOMINIO" A)
    while IFS= read -r linea; do
        local h; h=$(echo "$linea" | awk '{print $2}' | sed 's/\.$//')
        [[ -n "$h" ]] && agregar_ip "$(dig +short "$h" A | head -n 1)" "MX: $h"
    done < <(dig +short "$DOMINIO" MX)
    while IFS= read -r ns; do
        local h; h=$(echo "$ns" | sed 's/\.$//')
        [[ -n "$h" ]] && agregar_ip "$(dig +short "$h" A | head -n 1)" "NS: $h"
    done < <(dig +short "$DOMINIO" NS)

    echo -e "\n${VERDE}[+] Resultado DNS guardado en: $archivo_dns${NC}"
    echo -e "${AMARILLO}[*] Máquinas/IPs recopiladas listas para evaluación con Nmap:${NC}"
    if [[ ${#IPS_DETECTADAS[@]} -eq 0 ]]; then
        echo "  (Ninguna IPv4 resuelta todavía)"
    else
        for i in "${!IPS_DETECTADAS[@]}"; do
            echo "  [$((i+1))] ${IPS_DETECTADAS[$i]}"
        done
    fi
}

# ==============================================================================
# FASE 2: MENÚ NMAP (ESTADO, SERVICIOS/PUERTOS Y SCRIPTS NSE)
# ==============================================================================

seleccionar_objetivo_nmap() {
    echo -e "\n${CYAN}--- Selección de máquina objetivo para Nmap ---${NC}"
    if [[ ${#IPS_DETECTADAS[@]} -gt 0 ]]; then
        echo "Máquinas obtenidas en los registros DNS:"
        for i in "${!IPS_DETECTADAS[@]}"; do
            echo "  $((i+1)). ${IPS_DETECTADAS[$i]}"
        done
        echo "  0. Introducir otra IP o dominio manualmente"
        read -p "Elige el número de máquina [1-${#IPS_DETECTADAS[@]} o 0]: " sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#IPS_DETECTADAS[@]} )); then
            OBJETIVO=$(echo "${IPS_DETECTADAS[$((sel-1))]}" | awk '{print $1}')
            return
        fi
    else
        echo -e "${AMARILLO}[i] Aún no has recopilado IPs desde DNS (se usará $DOMINIO o la IP que indiques).${NC}"
    fi

    read -p "Introduce la IP o dominio objetivo para Nmap (Enter para usar $DOMINIO): " manual
    if [[ -z "$manual" ]]; then
        OBJETIVO="$DOMINIO"
    else
        OBJETIVO="$manual"
    fi
}

# Mapea servicio/puerto detectado al conjunto de scripts NSE adecuado
obtener_nse_por_servicio() {
    local puerto="$1"
    local servicio="$2"

    case "$servicio" in
        *http*|*www*)
            echo "http-title,http-headers,http-methods,http-server-header"
            ;;
        *ssl*|*https*)
            echo "ssl-cert,ssl-enum-ciphers,http-title,http-headers"
            ;;
        *ssh*)
            echo "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey"
            ;;
        *ftp*)
            echo "ftp-anon,ftp-syst,ftp-bounce"
            ;;
        *smtp*)
            echo "smtp-commands,smtp-enum-users,smtp-open-relay"
            ;;
        *domain*|*dns*)
            echo "dns-nsid,dns-recursion,dns-service-discovery"
            ;;
        *smb*|*microsoft-ds*|*netbios*)
            echo "smb-os-discovery,smb-security-mode,smb-enum-shares"
            ;;
        *mysql*)
            echo "mysql-info,mysql-empty-password"
            ;;
        *rdp*|*ms-wbt-server*)
            echo "rdp-enum-encryption,rdp-ntlm-info"
            ;;
        *)
            # Si el nombre de servicio es genérico, comprobar por número de puerto común
            case "$puerto" in
                80|8080|8000) echo "http-title,http-headers,http-methods" ;;
                443|8443)     echo "ssl-cert,ssl-enum-ciphers,http-title" ;;
                22)           echo "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey" ;;
                21)           echo "ftp-anon,ftp-syst" ;;
                25|465|587)   echo "smtp-commands,smtp-open-relay" ;;
                53)           echo "dns-nsid,dns-recursion" ;;
                139|445)      echo "smb-os-discovery,smb-security-mode" ;;
                *)            echo "default,safe" ;;
            esac
            ;;
    esac
}

menu_nmap() {
    seleccionar_objetivo_nmap
    local archivo_servicios="${DIR_RESULTADOS}/nmap_servicios_${OBJETIVO}.txt"

    while true; do
        echo -e "\n${CYAN}============================================================${NC}"
        echo -e "${VERDE}  MENÚ DE AUDITORÍA NMAP + NSE  |  Objetivo: ${AMARILLO}$OBJETIVO${NC}"
        echo -e "${CYAN}============================================================${NC}"
        echo "1. Determinar estado de la máquina (Host Discovery)"
        echo "2. Detectar puertos abiertos, servicios y versiones (-sV)"
        echo "3. Evaluar automáticamente con NSE según puertos y servicios detectados"
        echo "4. Seleccionar manualmente script NSE por tipo de servicio"
        echo "5. Auditoría completa encadenada (Estado -> Servicios -> NSE)"
        echo "6. Cambiar máquina objetivo"
        echo "------------------------------------------------------------"
        echo "0. Volver al menú principal DNS"

        read -p "¿Qué opción de Nmap eliges? " op_nmap

        case "$op_nmap" in
            1)
                echo -e "\n${AZUL}[*] Comprobando estado de la máquina $OBJETIVO...${NC}"
                nmap -sn -PE -PS22,80,443 "$OBJETIVO" | tee "${DIR_RESULTADOS}/nmap_estado_${OBJETIVO}.txt"
                ;;
            2)
                echo -e "\n${AZUL}[*] Escaneando puertos abiertos y versiones de servicios en $OBJETIVO...${NC}"
                nmap -Pn -sT -sV --open -T3 -p 21,22,25,53,80,110,139,143,443,445,587,3306,3389,8080,8443 "$OBJETIVO" | tee "$archivo_servicios"
                echo -e "${VERDE}[+] Resultados guardados en: $archivo_servicios${NC}"
                ;;
            3)
                if [[ ! -f "$archivo_servicios" ]]; then
                    echo -e "${AMARILLO}[!] No existe escaneo previo de servicios. Ejecutando detección primero...${NC}"
                    nmap -Pn -sT -sV --open -T3 -p 21,22,25,53,80,110,139,143,443,445,587,3306,3389,8080,8443 "$OBJETIVO" | tee "$archivo_servicios"
                fi

                echo -e "\n${AZUL}[*] Analizando puertos y servicios detectados para aplicar NSE correspondiente...${NC}"
                local lineas_puertos
                lineas_puertos=$(grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open" "$archivo_servicios")

                if [[ -z "$lineas_puertos" ]]; then
                    echo -e "${ROJO}[!] No se detectaron puertos abiertos en $OBJETIVO.${NC}"
                else
                    local archivo_nse="${DIR_RESULTADOS}/nmap_nse_${OBJETIVO}.txt"
                    echo "=== EVALUACIÓN NSE AUTOMÁTICA: $OBJETIVO ($(date)) ===" > "$archivo_nse"
                    while IFS= read -r linea; do
                        local puerto servicio scripts_nse
                        puerto=$(echo "$linea" | awk -F'/' '{print $1}')
                        servicio=$(echo "$linea" | awk '{print $3}')
                        scripts_nse=$(obtener_nse_por_servicio "$puerto" "$servicio")

                        echo -e "\n${VERDE}[+] Puerto $puerto ($servicio) -> Ejecutando NSE: ${AMARILLO}$scripts_nse${NC}"
                        nmap -Pn -sT -p "$puerto" -sV --script="$scripts_nse" "$OBJETIVO" | tee -a "$archivo_nse"
                    done <<< "$lineas_puertos"
                    echo -e "\n${VERDE}[+] Evaluación NSE guardada en: $archivo_nse${NC}"
                fi
                ;;
            4)
                echo -e "\n${CYAN}--- Selección manual de scripts NSE ---${NC}"
                echo "1. HTTP / HTTPS (puertos 80,443) -> http-title,http-headers,http-methods,ssl-cert"
                echo "2. SSH (puerto 22)               -> ssh2-enum-algos,ssh-auth-methods,ssh-hostkey"
                echo "3. Correo SMTP (puertos 25,587)  -> smtp-commands,smtp-open-relay"
                echo "4. FTP (puerto 21)               -> ftp-anon,ftp-syst"
                echo "5. DNS (puerto 53)               -> dns-nsid,dns-recursion"
                echo "6. SMB (puertos 139,445)         -> smb-os-discovery,smb-security-mode,smb-enum-shares"
                echo "7. Evaluación general de vulnerabilidades (--script=vuln)"
                read -p "Elige el perfil NSE [1-7]: " op_nse
                case "$op_nse" in
                    1) nmap -Pn -sT -p 80,443 -sV --script="http-title,http-headers,http-methods,ssl-cert" "$OBJETIVO" ;;
                    2) nmap -Pn -sT -p 22 -sV --script="ssh2-enum-algos,ssh-auth-methods,ssh-hostkey" "$OBJETIVO" ;;
                    3) nmap -Pn -sT -p 25,587 -sV --script="smtp-commands,smtp-open-relay" "$OBJETIVO" ;;
                    4) nmap -Pn -sT -p 21 -sV --script="ftp-anon,ftp-syst" "$OBJETIVO" ;;
                    5) nmap -Pn -sT -p 53 -sV --script="dns-nsid,dns-recursion" "$OBJETIVO" ;;
                    6) nmap -Pn -sT -p 139,445 -sV --script="smb-os-discovery,smb-security-mode,smb-enum-shares" "$OBJETIVO" ;;
                    7) nmap -Pn -sT -sV -p 21,22,25,53,80,110,139,143,443,445,587,3306,3389,8080,8443 --script="vuln" "$OBJETIVO" ;;
                    *) echo -e "${ROJO}Opción NSE no válida.${NC}" ;;
                esac
                ;;
            5)
                echo -e "\n${CYAN}=== AUDITORÍA COMPLETA ENCADENADA SOBRE $OBJETIVO ===${NC}"
                echo -e "\n${AZUL}[1/3] Estado de la máquina:${NC}"
                nmap -sn -PE -PS22,80,443 "$OBJETIVO" | tee "${DIR_RESULTADOS}/nmap_estado_${OBJETIVO}.txt"
                echo -e "\n${AZUL}[2/3] Puertos abiertos y servicios:${NC}"
                nmap -Pn -sT -sV --open -T3 -p 21,22,25,53,80,110,139,143,443,445,587,3306,3389,8080,8443 "$OBJETIVO" | tee "$archivo_servicios"
                echo -e "\n${AZUL}[3/3] Evaluación NSE por servicio y puerto:${NC}"
                local lineas_puertos
                lineas_puertos=$(grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open" "$archivo_servicios")
                if [[ -n "$lineas_puertos" ]]; then
                    local archivo_nse="${DIR_RESULTADOS}/nmap_nse_${OBJETIVO}.txt"
                    echo "=== EVALUACIÓN NSE AUTOMÁTICA: $OBJETIVO ($(date)) ===" > "$archivo_nse"
                    while IFS= read -r linea; do
                        local puerto servicio scripts_nse
                        puerto=$(echo "$linea" | awk -F'/' '{print $1}')
                        servicio=$(echo "$linea" | awk '{print $3}')
                        scripts_nse=$(obtener_nse_por_servicio "$puerto" "$servicio")
                        echo -e "\n${VERDE}[+] Puerto $puerto ($servicio) -> NSE: ${AMARILLO}$scripts_nse${NC}"
                        nmap -Pn -sT -p "$puerto" -sV --script="$scripts_nse" "$OBJETIVO" | tee -a "$archivo_nse"
                    done <<< "$lineas_puertos"
                    echo -e "\n${VERDE}[+] Informe completo guardado en $DIR_RESULTADOS/${NC}"
                else
                    echo -e "${ROJO}[!] No se encontraron puertos abiertos para evaluar con NSE.${NC}"
                fi
                ;;
            6)
                seleccionar_objetivo_nmap
                archivo_servicios="${DIR_RESULTADOS}/nmap_servicios_${OBJETIVO}.txt"
                ;;
            0)
                echo -e "${AMARILLO}Volviendo al menú principal...${NC}"
                break
                ;;
            *)
                echo -e "${ROJO}Error en tu selección, por favor vuelve a intentarlo.${NC}"
                ;;
        esac
    done
}

# ==============================================================================
# BUCLE PRINCIPAL DE LA APLICACIÓN
# ==============================================================================

comprobar_dependencias
pedir_dominio

# Tendrás un while con el que siempre tendremos la opción de trabajar
# con los elementos del menú DNS y pasar a la evaluación con Nmap + NSE
while true; do
    echo -e "\n${CYAN}============================================================${NC}"
    echo -e "${VERDE}  HERRAMIENTA DNS + NMAP NSE  |  Dominio actual: ${AMARILLO}$DOMINIO${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo "Opciones disponibles en la herramienta:"
    echo "  1. Consulta de IP (Registros A / AAAA)"
    echo "  2. Consulta de servidores de correo (Registro MX)"
    echo "  3. Consulta de servidores de nombres (Registro NS)"
    echo "  4. Consulta de registros TXT y SOA (datos sensibles)"
    echo "  5. Reconocimiento DNS completo (todos los registros)"
    echo "  6. Iniciar menú Nmap + NSE sobre máquina detectada"
    echo "  7. Cambiar dominio objetivo"
    echo "------------------------------------------------------------"
    echo "  0. Salir de la herramienta"

    read -p "¿Qué opción eliges? " opcion

    case "$opcion" in
        1) consulta_ip ;;
        2) consulta_mx ;;
        3) consulta_ns ;;
        4) consulta_txt_soa ;;
        5) consulta_dns_completa ;;
        6) menu_nmap ;;
        7) pedir_dominio ;;
        0)
            echo -e "${VERDE}Saliendo de la herramienta....${NC}"
            exit 0
            ;;
        *)
            echo -e "${ROJO}Error en tu selección, por favor vuelve a intentarlo.${NC}"
            ;;
    esac
done
