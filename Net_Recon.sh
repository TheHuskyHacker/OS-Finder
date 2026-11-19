#!/bin/bash
# net-recon.sh — Scan a subnet for Linux, Windows & Active Directory hosts
# Uses ping (TTL fingerprinting) + port checks + AD detection
# Usage: ./net-recon.sh <subnet> [options]
# Example: ./net-recon.sh 192.168.1.0/24 -p

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║          Net Recon Scanner v2.0              ║"
    echo "║          by The Husky Hacker                 ║"
    echo "║                                              ║"
    echo "║   Linux  |  Windows  |  Active Directory     ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo -e "Usage: ${BOLD}$0 <subnet>${NC} [options]"
    echo ""
    echo -e "  subnet       CIDR notation (e.g. 192.168.1.0/24)"
    echo ""
    echo -e "Options:"
    echo -e "  -p           Run port fingerprint on all discovered hosts"
    echo -e "  -t <sec>     Ping timeout in seconds (default: 1)"
    echo -e "  -o <file>    Save results to file"
    echo -e "  -h           Show this help"
    exit 1
}

# --- Defaults ---
PORTSCAN=false
TIMEOUT=1
OUTFILE=""

# --- Port lists ---
LINUX_PORTS=(22 80 111 443 2049 3306 5432 8080 8443 9090)
WINDOWS_PORTS=(135 139 445 3389 5985 5986 47001)
AD_PORTS=(53 88 389 636 3268 3269 464 9389)

# --- Parse args ---
while getopts "pt:o:h" opt; do
    case $opt in
        p) PORTSCAN=true ;;
        t) TIMEOUT="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

SUBNET="$1"
[[ -z "$SUBNET" ]] && usage

banner

# --- Logging ---
log() {
    echo -e "$1"
    if [[ -n "$OUTFILE" ]]; then
        echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTFILE"
    fi
}

# --- Expand CIDR to host list ---
expand_cidr() {
    local cidr="$1"
    local base mask

    base=$(echo "$cidr" | cut -d'/' -f1)
    mask=$(echo "$cidr" | cut -d'/' -f2)

    IFS='.' read -r a b c d <<< "$base"
    ip_dec=$(( (a << 24) + (b << 16) + (c << 8) + d ))

    local hostbits=$(( 32 - mask ))
    local num_hosts=$(( (1 << hostbits) ))
    start=$(( ip_dec & ( (0xFFFFFFFF << hostbits) & 0xFFFFFFFF ) ))
    end=$(( start + num_hosts - 1 ))

    if [[ $hostbits -ge 2 ]]; then
        start=$(( start + 1 ))
        end=$(( end - 1 ))
    fi

    for (( i = start; i <= end; i++ )); do
        printf "%d.%d.%d.%d\n" \
            $(( (i >> 24) & 255 )) \
            $(( (i >> 16) & 255 )) \
            $(( (i >> 8) & 255 )) \
            $(( i & 255 ))
    done
}

# --- TTL-based OS guess ---
guess_os() {
    local ttl="$1"
    if [[ $ttl -le 64 && $ttl -ge 1 ]]; then
        echo "Linux"
    elif [[ $ttl -le 128 && $ttl -ge 65 ]]; then
        echo "Windows"
    elif [[ $ttl -le 255 && $ttl -ge 129 ]]; then
        echo "Network"
    else
        echo "Unknown"
    fi
}

# --- Quick port check ---
check_port() {
    local host="$1"
    local port="$2"
    timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    return $?
}

# --- Check ports from a list, return open ones ---
scan_ports() {
    local host="$1"
    shift
    local ports=("$@")
    local open=""
    for port in "${ports[@]}"; do
        if check_port "$host" "$port"; then
            open+=" $port"
        fi
    done
    echo "$open"
}

# --- Detect if host is a Domain Controller ---
detect_dc() {
    local host="$1"
    local dc_score=0
    local dc_signs=""

    # Kerberos (88)
    if check_port "$host" 88; then
        dc_score=$((dc_score + 3))
        dc_signs+="Kerberos(88) "
    fi

    # LDAP (389)
    if check_port "$host" 389; then
        dc_score=$((dc_score + 3))
        dc_signs+="LDAP(389) "
    fi

    # LDAPS (636)
    if check_port "$host" 636; then
        dc_score=$((dc_score + 2))
        dc_signs+="LDAPS(636) "
    fi

    # DNS (53)
    if check_port "$host" 53; then
        dc_score=$((dc_score + 2))
        dc_signs+="DNS(53) "
    fi

    # Global Catalog (3268)
    if check_port "$host" 3268; then
        dc_score=$((dc_score + 3))
        dc_signs+="GC(3268) "
    fi

    # Global Catalog SSL (3269)
    if check_port "$host" 3269; then
        dc_score=$((dc_score + 2))
        dc_signs+="GC-SSL(3269) "
    fi

    # Kerberos kpasswd (464)
    if check_port "$host" 464; then
        dc_score=$((dc_score + 2))
        dc_signs+="kpasswd(464) "
    fi

    # AD Web Services (9389)
    if check_port "$host" 9389; then
        dc_score=$((dc_score + 2))
        dc_signs+="ADWS(9389) "
    fi

    # SMB (445) — expected on DC
    if check_port "$host" 445; then
        dc_score=$((dc_score + 1))
        dc_signs+="SMB(445) "
    fi

    if [[ $dc_score -ge 8 ]]; then
        echo "DC_CONFIRMED|$dc_signs"
    elif [[ $dc_score -ge 4 ]]; then
        echo "DC_LIKELY|$dc_signs"
    else
        echo "NOT_DC|$dc_signs"
    fi
}

# --- Detect Windows role ---
detect_windows_role() {
    local host="$1"
    local role=""
    local details=""

    # Check for DC first
    local dc_result
    dc_result=$(detect_dc "$host")
    local dc_status="${dc_result%%|*}"
    local dc_ports="${dc_result##*|}"

    if [[ "$dc_status" == "DC_CONFIRMED" ]]; then
        role="Domain Controller"
        details="$dc_ports"
    elif [[ "$dc_status" == "DC_LIKELY" ]]; then
        role="Possible DC"
        details="$dc_ports"
    else
        # Check other Windows services
        local win_services=""
        if check_port "$host" 3389; then win_services+="RDP(3389) "; fi
        if check_port "$host" 5985; then win_services+="WinRM(5985) "; fi
        if check_port "$host" 5986; then win_services+="WinRM-S(5986) "; fi
        if check_port "$host" 1433; then win_services+="MSSQL(1433) "; fi
        if check_port "$host" 445; then win_services+="SMB(445) "; fi
        if check_port "$host" 135; then win_services+="RPC(135) "; fi
        if check_port "$host" 139; then win_services+="NetBIOS(139) "; fi
        if check_port "$host" 80; then win_services+="HTTP(80) "; fi
        if check_port "$host" 443; then win_services+="HTTPS(443) "; fi
        if check_port "$host" 47001; then win_services+="WinRM-Compat(47001) "; fi

        if [[ -n "$win_services" ]]; then
            role="Windows Host"
            details="$win_services"
        else
            role="Windows Host"
            details="(no common ports open)"
        fi
    fi

    echo "$role|$details"
}

# --- Try to grab domain name via LDAP/SMB ---
grab_domain_hint() {
    local host="$1"

    # Try LDAP NULL bind for domain info
    if command -v ldapsearch &>/dev/null && check_port "$host" 389; then
        local ldap_out
        ldap_out=$(timeout 3 ldapsearch -x -H "ldap://$host" -s base namingContexts 2>/dev/null | grep -i "namingContexts" | head -1)
        if [[ -n "$ldap_out" ]]; then
            echo "$ldap_out" | sed 's/namingContexts: //;s/DC=//g;s/,/./g'
            return
        fi
    fi

    # Try DNS reverse lookup
    if command -v nslookup &>/dev/null; then
        local dns_out
        dns_out=$(timeout 2 nslookup "$host" "$host" 2>/dev/null | grep -i "name" | head -1 | awk '{print $NF}' | sed 's/\.$//')
        if [[ -n "$dns_out" ]]; then
            echo "$dns_out"
            return
        fi
    fi

    echo ""
}

# =============================================
#                MAIN SCAN
# =============================================

log "${YELLOW}[*]${NC} Target:    ${BOLD}$SUBNET${NC}"
log "${YELLOW}[*]${NC} Timeout:   ${TIMEOUT}s"
log "${YELLOW}[*]${NC} Port scan: $PORTSCAN"
[[ -n "$OUTFILE" ]] && log "${YELLOW}[*]${NC} Output:    $OUTFILE" && echo "" > "$OUTFILE"
log ""

HOSTS=$(expand_cidr "$SUBNET")
TOTAL=$(echo "$HOSTS" | wc -l)
log "${YELLOW}[*]${NC} Scanning $TOTAL hosts..."
log ""

# Counters
FOUND_LINUX=0
FOUND_WINDOWS=0
FOUND_DC=0
FOUND_OTHER=0

# Result arrays
LINUX_HOSTS=""
WINDOWS_HOSTS=""
DC_HOSTS=""

while IFS= read -r ip; do
    ping_out=$(ping -c 1 -W "$TIMEOUT" "$ip" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        ttl=$(echo "$ping_out" | grep -oP 'ttl=\K[0-9]+')
        os=$(guess_os "$ttl")

        case "$os" in
            Linux)
                log "${GREEN}[+]${NC} ${BOLD}$ip${NC} — TTL=$ttl → ${GREEN}Linux${NC}"
                FOUND_LINUX=$((FOUND_LINUX + 1))

                if [[ "$PORTSCAN" == true ]]; then
                    open=$(scan_ports "$ip" "${LINUX_PORTS[@]}")
                    [[ -n "$open" ]] && log "    ${CYAN}Services:${NC}$open"
                fi

                LINUX_HOSTS+="$ip\n"
                ;;

            Windows)
                # Deeper Windows analysis
                local_result=$(detect_windows_role "$ip")
                local_role="${local_result%%|*}"
                local_details="${local_result##*|}"

                if [[ "$local_role" == "Domain Controller" ]]; then
                    log "${RED}[★]${NC} ${BOLD}$ip${NC} — TTL=$ttl → ${RED}${BOLD}DOMAIN CONTROLLER${NC}"
                    log "    ${MAGENTA}AD Services:${NC} $local_details"

                    # Try to grab domain name
                    domain=$(grab_domain_hint "$ip")
                    if [[ -n "$domain" ]]; then
                        log "    ${MAGENTA}Domain:${NC} $domain"
                    fi

                    FOUND_DC=$((FOUND_DC + 1))
                    DC_HOSTS+="$ip\n"

                elif [[ "$local_role" == "Possible DC" ]]; then
                    log "${YELLOW}[?]${NC} ${BOLD}$ip${NC} — TTL=$ttl → ${YELLOW}${BOLD}Possible Domain Controller${NC}"
                    log "    ${MAGENTA}AD Indicators:${NC} $local_details"
                    FOUND_DC=$((FOUND_DC + 1))
                    DC_HOSTS+="$ip\n"

                else
                    log "${BLUE}[+]${NC} ${BOLD}$ip${NC} — TTL=$ttl → ${BLUE}Windows${NC}"
                    FOUND_WINDOWS=$((FOUND_WINDOWS + 1))

                    if [[ "$PORTSCAN" == true ]]; then
                        log "    ${CYAN}Services:${NC} $local_details"
                    fi

                    WINDOWS_HOSTS+="$ip\n"
                fi
                ;;

            *)
                log "${YELLOW}[-]${NC} $ip — TTL=$ttl → ${YELLOW}$os${NC}"
                FOUND_OTHER=$((FOUND_OTHER + 1))
                ;;
        esac
    fi
done <<< "$HOSTS"

# =============================================
#                SUMMARY
# =============================================

log ""
log "${CYAN}══════════════════════════════════════════════════${NC}"
log "${BOLD} Scan Complete${NC}"
log "${CYAN}══════════════════════════════════════════════════${NC}"
log ""
log " ${RED}★ Domain Controllers:  ${FOUND_DC}${NC}"
log " ${BLUE}■ Windows hosts:       ${FOUND_WINDOWS}${NC}"
log " ${GREEN}■ Linux hosts:         ${FOUND_LINUX}${NC}"
log " ${YELLOW}■ Other:               ${FOUND_OTHER}${NC}"
log " Total alive:            $((FOUND_DC + FOUND_WINDOWS + FOUND_LINUX + FOUND_OTHER))"

if [[ $FOUND_DC -gt 0 ]]; then
    log ""
    log "${RED}${BOLD} ★ Domain Controllers:${NC}"
    echo -e "$DC_HOSTS" | sed '/^$/d' | while read -r line; do
        log "   → $line"
    done
fi

if [[ $FOUND_WINDOWS -gt 0 ]]; then
    log ""
    log "${BLUE}${BOLD} ■ Windows Targets:${NC}"
    echo -e "$WINDOWS_HOSTS" | sed '/^$/d' | while read -r line; do
        log "   → $line"
    done
fi

if [[ $FOUND_LINUX -gt 0 ]]; then
    log ""
    log "${GREEN}${BOLD} ■ Linux Targets:${NC}"
    echo -e "$LINUX_HOSTS" | sed '/^$/d' | while read -r line; do
        log "   → $line"
    done
fi

log ""

if [[ -n "$OUTFILE" ]]; then
    log "${YELLOW}[*]${NC} Results saved to: $OUTFILE"
    log ""
fi
