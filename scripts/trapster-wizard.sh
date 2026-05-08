#!/usr/bin/env bash
# Interactive Trapster configuration wizard (bash).
# Uses trapster/data/trapster.conf as the template — no duplicated service list in this script.
set -euo pipefail

readonly C_RESET=$'\033[0m'
readonly C_BOLD=$'\033[1m'
readonly C_DIM=$'\033[2m'
readonly C_RED=$'\033[0;31m'
readonly C_GREEN=$'\033[0;32m'
readonly C_YELLOW=$'\033[0;33m'
readonly C_BLUE=$'\033[0;34m'
readonly C_CYAN=$'\033[0;36m'

# All Trapster protocols (fixed order; display ports are standard / well-known)
TRAPSTER_SERVICES=( ftp http https ssh dns vnc mysql mssql postgres ldap ldaps rdp telnet snmp rsync )
TRAPSTER_PORTS=( 21 80 443 22 53 5900 3306 1433 5432 389 636 3389 23 161 873 )

usage() {
  echo "Usage: $0 [--template PATH]"
  echo "  --template  JSON template (default: repo trapster/data/trapster.conf)"
  echo "  Writes: ./trapster.generated.conf (current directory)"
  exit "${1:-0}"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE="${REPO_ROOT}/trapster/data/trapster.conf"
# Full service definitions when the chosen template omits a protocol
SERVICE_DEFAULTS_LIB="${REPO_ROOT}/trapster/data/trapster.conf"
readonly OUTPUT="${PWD}/trapster.generated.conf"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --template) TEMPLATE="$2"; shift 2 ;;
    -h|--help)  usage 0 ;;
    *) echo "Unknown option: $1"; usage 1 ;;
  esac
done

if [[ ! -f "$TEMPLATE" ]]; then
  echo -e "${C_RED}Template not found: ${TEMPLATE}${C_RESET}" >&2
  exit 1
fi

need_python() {
  if ! command -v python3 &>/dev/null; then
    echo -e "${C_RED}python3 is required for JSON handling.${C_RESET}" >&2
    exit 1
  fi
}

need_python

banner() {
  echo -e "${C_CYAN}${C_BOLD}═══════════════════════════════════════════════════════════${C_RESET}"
  echo -e "${C_CYAN}${C_BOLD}  Trapster configuration wizard${C_RESET}"
  echo -e "${C_DIM}  Template: ${TEMPLATE}${C_RESET}"
  echo -e "${C_CYAN}${C_BOLD}═══════════════════════════════════════════════════════════${C_RESET}"
  echo ""
}

prompt() {
  # $1 label, $2 default
  local label="$1"
  local default="$2"
  local val
  echo -ne "${C_GREEN}${label}${C_RESET} ${C_DIM}[${default}]${C_RESET}: " >&2
  read -r val
  if [[ -z "$val" ]]; then
    echo "$default"
  else
    echo "$val"
  fi
}

prompt_yn() {
  # $1 message, $2 default y/N
  local msg="$1"
  local def="${2:-n}"
  local hint="y/N"
  [[ "$def" == "y" ]] && hint="Y/n"
  while true; do
    echo -ne "${C_YELLOW}${msg}${C_RESET} ${C_DIM}[${hint}]${C_RESET}: " >&2
    read -r r
    r="${r:-$def}"
    r="${r,,}"
    case "$r" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) echo -e "${C_DIM}Please answer y or n.${C_RESET}" >&2 ;;
    esac
  done
}

show_json() {
  python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), indent=2))' "$1"
}

# --- interfaces ---
pick_interface() {
  local default="$1"
  local -a names=()
  if command -v ip &>/dev/null; then
    mapfile -t names < <(ip -o link show 2>/dev/null | awk -F': ' '$2 != "lo" && /state UP|state UNKNOWN/ {print $2}' | head -n 50)
  fi

  echo -e "\n${C_BOLD}Available interfaces${C_RESET}" >&2
  echo -e "${C_DIM}#  Interface          IPv4${C_RESET}" >&2
  echo -e "  ${C_CYAN}0${C_RESET}  ${C_BOLD}(all)${C_RESET}              0.0.0.0" >&2
  local i=1 dev ips
  for dev in "${names[@]}"; do
    ips=$(ip -o -4 addr show "$dev" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd', ' -)
    [[ -z "$ips" ]] && ips="-"
    printf "  ${C_CYAN}%d${C_RESET}  %-18s %s\n" "$i" "$dev" "$ips" >&2
    ((i++)) || true
  done
  if [[ ${#names[@]} -eq 0 ]] && command -v ip &>/dev/null; then
    echo -e "${C_DIM}(no non-loopback interfaces in UP/UNKNOWN state)${C_RESET}" >&2
  elif [[ ${#names[@]} -eq 0 ]]; then
    echo -e "${C_DIM}(install 'ip' for interface list; enter name manually)${C_RESET}" >&2
  fi

  local max=${#names[@]}
  while true; do
    echo -ne "\n${C_GREEN}Interface # or name${C_RESET} ${C_DIM}(Enter = all / '${default}')${C_RESET}: " >&2
    read -r choice
    if [[ -z "$choice" ]]; then
      echo "$default"
      return
    fi
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
      local n=$((10#$choice))
      if (( n == 0 )); then
        echo ""
        return
      fi
      if (( max > 0 && n >= 1 && n <= max )); then
        echo "${names[$((n - 1))]}"
        return
      fi
      if (( max == 0 )); then
        echo -e "${C_RED}No numbered interfaces listed. Enter the interface name, or leave empty for default.${C_RESET}" >&2
        continue
      fi
      echo -e "${C_RED}Invalid interface number: ${choice} (use 0-${max}).${C_RESET}" >&2
      continue
    fi
    echo "$choice"
    return
  done
}

# Extract top-level string / list default from template via python
get_tpl_string() {
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); v=d.get(sys.argv[2],''); print('' if v is None else v)" "$TEMPLATE" "$1"
}

get_tpl_list_csv() {
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); v=d.get(sys.argv[2],[]); print(','.join(str(x) for x in v) if isinstance(v,list) else '')" "$TEMPLATE" "$1"
}

update_service_port_at() {
  local svc="$1"
  local idx="$2"
  local port="$3"
  python3 -c "
import json,sys
path, svc, idx, port = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
d=json.load(open(path))
d['services'][svc][idx]['port']=port
json.dump(d, open(path,'w'), indent=2)
" "$STATE_FILE" "$svc" "$idx" "$port"
}

service_instance_json() {
  local cfg="$1"
  local svc="$2"
  local idx="$3"
  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
svc, idx = sys.argv[2], int(sys.argv[3])
print(json.dumps(d['services'][svc][idx], indent=2))
" "$cfg" "$svc" "$idx"
}

count_service_blocks() {
  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(sum(len(v) for v in d.get('services',{}).values()))
" "$1"
}

# Merge globals + logger + selected services into STATE_FILE
STATE_FILE="$(mktemp)"
trap 'rm -f "$STATE_FILE"' EXIT

python3 -c "
import json,sys
tpl_path=sys.argv[1]
out_path=sys.argv[2]
with open(tpl_path) as f:
    d=json.load(f)
d['services'] = {}
with open(out_path,'w') as f:
    json.dump(d,f,indent=2)
" "$TEMPLATE" "$STATE_FILE"

banner

echo -e "${C_BOLD}Global settings${C_RESET}"
ID="$(prompt "Node id" "$(get_tpl_string id)")"
DESC="$(prompt "Description" "$(get_tpl_string description)")"
IFACE_DEFAULT="$(get_tpl_string interface)"
echo -e "${C_DIM}Tip: hostname and domain help Windows-oriented deception (LDAP/LDAPS/RDP).${C_RESET}"
HOST="$(prompt "Hostname" "$(get_tpl_string hostname)")"
DOM="$(prompt "Domain" "$(get_tpl_string domain)")"
WL="$(prompt "Whitelist IPs (comma-separated)" "$(get_tpl_list_csv whitelist_ips)")"
IFACE="$(pick_interface "$IFACE_DEFAULT")"

python3 -c "
import json,sys
p=sys.argv[1]
d=json.load(open(p))
d['id']=sys.argv[2]
d['description']=sys.argv[3]
d['hostname']=sys.argv[4]
d['domain']=sys.argv[5]
d['interface']=sys.argv[6]
ips=[x.strip() for x in sys.argv[7].split(',') if x.strip()]
d['whitelist_ips']=ips
json.dump(d,open(p,'w'),indent=2)
" "$STATE_FILE" "$ID" "$DESC" "$HOST" "$DOM" "$IFACE" "$WL"

echo -e "\n${C_BOLD}Services${C_RESET}"
echo -e "${C_DIM}Add listeners one by one. You can add the same protocol several times (e.g. multiple HTTP ports).${C_RESET}"
echo -e "${C_DIM}Reference port shown; new blocks copy the template when present, else ${SERVICE_DEFAULTS_LIB}.${C_RESET}"

show_service_catalog() {
  local j=0
  for s in "${TRAPSTER_SERVICES[@]}"; do
    p="${TRAPSTER_PORTS[$j]}"
    printf "  ${C_CYAN}%2d${C_RESET}  %-14s  port ${C_BOLD}%s${C_RESET}\n" "$((j + 1))" "$s" "$p" >&2
    ((j++)) || true
  done
}

NSVC=${#TRAPSTER_SERVICES[@]}
while true; do
  nblk="$(count_service_blocks "$STATE_FILE")"
  if (( nblk == 0 )); then
    yn_msg="Add a service?"
    yn_def="y"
  else
    yn_msg="Add another service?"
    yn_def="n"
  fi
  if ! prompt_yn "$yn_msg" "$yn_def"; then
    break
  fi

  show_service_catalog
  SVC_NAME=""
  while [[ -z "$SVC_NAME" ]]; do
    echo -ne "\n${C_GREEN}Service type #${C_RESET} ${C_DIM}(1-${NSVC})${C_RESET}: " >&2
    read -r pick
    if [[ "$pick" =~ ^[0-9]+$ ]]; then
      pn=$((10#$pick))
      if (( pn >= 1 && pn <= NSVC )); then
        SVC_NAME="${TRAPSTER_SERVICES[$((pn - 1))]}"
      fi
    fi
    [[ -z "$SVC_NAME" ]] && echo -e "${C_RED}Enter a number from 1 to ${NSVC}.${C_RESET}" >&2
  done

  python3 - "$STATE_FILE" "$SVC_NAME" "$TEMPLATE" "$SERVICE_DEFAULTS_LIB" <<'PY'
import copy, json, sys
path, name, tpl_path, lib_path = sys.argv[1:5]
with open(path, encoding="utf-8") as f:
    d = json.load(f)
with open(tpl_path, encoding="utf-8") as f:
    tpl_svcs = json.load(f).get("services", {})
try:
    with open(lib_path, encoding="utf-8") as f:
        lib_svcs = json.load(f).get("services", {})
except OSError:
    lib_svcs = {}
if name in tpl_svcs and tpl_svcs[name]:
    block = copy.deepcopy(tpl_svcs[name][0])
elif name in lib_svcs and lib_svcs[name]:
    block = copy.deepcopy(lib_svcs[name][0])
else:
    sys.stderr.write("wizard: no default block for service %r\n" % (name,))
    sys.exit(1)
d.setdefault("services", {})
d["services"].setdefault(name, [])
d["services"][name].append(block)
with open(path, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=2)
PY

  IDX="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d['services'][sys.argv[2]])-1)" "$STATE_FILE" "$SVC_NAME")"
  TOT="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d['services'][sys.argv[2]]))" "$STATE_FILE" "$SVC_NAME")"
  echo -e "\n${C_BOLD}--- ${SVC_NAME} (instance ${C_CYAN}$((IDX + 1))${C_RESET}${C_BOLD} of ${TOT}) ---${C_RESET}"
  TMP_SVC="$(mktemp)"
  service_instance_json "$STATE_FILE" "$SVC_NAME" "$IDX" > "$TMP_SVC"
  echo -e "${C_BLUE}Configuration for this listener:${C_RESET}"
  show_json "$TMP_SVC" | sed 's/^/  /'
  rm -f "$TMP_SVC"

  if ! prompt_yn "Use this configuration as-is?" "y"; then
    CUR_PORT="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['services'][sys.argv[2]][int(sys.argv[3])].get('port',0))" "$STATE_FILE" "$SVC_NAME" "$IDX")"
    NEW_PORT="$(prompt "Port" "$CUR_PORT")"
    if [[ -n "$NEW_PORT" ]] && [[ "$NEW_PORT" != "$CUR_PORT" ]]; then
      update_service_port_at "$SVC_NAME" "$IDX" "$NEW_PORT"
    fi
  fi
  echo -e "${C_DIM}Edit other keys in ${OUTPUT} after generation if needed.${C_RESET}"
done

if (( $(count_service_blocks "$STATE_FILE") < 1 )); then
  echo -e "${C_RED}At least one service listener is required.${C_RESET}" >&2
  exit 1
fi

echo -e "\n${C_BOLD}Logger${C_RESET}"
echo -e "${C_DIM}Output: terminal | file | api | redis — Format: default | ecs${C_RESET}"
OUT_CH="$(prompt "Output (terminal/file/api/redis)" "$(python3 -c "import json;print(json.load(open('$STATE_FILE')).get('logger',{}).get('output','terminal'))")")"
FMT_CH="$(prompt "Format (default/ecs)" "default")"

LOG_KWARGS="{}"
case "$OUT_CH" in
  file)
    LF="$(prompt "Log file" "/var/log/trapster-community.log")"
    LM="$(prompt "Mode" "a")"
    LOG_KWARGS="$(python3 -c "import json,sys; print(json.dumps({'logfile':sys.argv[1],'mode':sys.argv[2]}))" "$LF" "$LM")"
    ;;
  api)
    URL="$(prompt "API URL" "http://localhost:8080/logs")"
    LOG_KWARGS="$(python3 -c "import json,sys; print(json.dumps({'url':sys.argv[1],'headers':{}}))" "$URL")"
    ;;
  redis)
    RH="$(prompt "Redis host" "localhost")"
    RP="$(prompt "Redis port" "6379")"
    LOG_KWARGS="$(python3 -c "import json,sys; print(json.dumps({'host':sys.argv[1],'port':int(sys.argv[2])}))" "$RH" "$RP")"
    ;;
esac

if [[ "$FMT_CH" == "ecs" ]]; then
  LOG_KWARGS="$(python3 -c "
import json,sys
k=json.loads(sys.argv[1])
with open(sys.argv[2]) as f:
    tpl=json.load(f)
t_kw=tpl.get('logger',{}).get('kwargs',{})
k['ecs_version']=t_kw.get('ecs_version','8.11.0')
k['observer_name']=t_kw.get('observer_name','Trapster')
print(json.dumps(k))
" "$LOG_KWARGS" "$TEMPLATE")"
fi

python3 -c "
import json,sys
p=sys.argv[1]
d=json.load(open(p))
d['logger']={'output':sys.argv[2],'format':sys.argv[3],'kwargs':json.loads(sys.argv[4])}
json.dump(d,open(p,'w'),indent=2)
" "$STATE_FILE" "$OUT_CH" "$FMT_CH" "$LOG_KWARGS"

cp "$STATE_FILE" "$OUTPUT"
echo -e "\n${C_GREEN}Configuration written to:${C_RESET} $(realpath "$OUTPUT" 2>/dev/null || echo "$OUTPUT")"
echo -e "\n${C_BOLD}Start with Python:${C_RESET}"
echo -e "  python3 main.py -c \"$(realpath "$OUTPUT" 2>/dev/null || echo "$OUTPUT")\""
echo -e "\n${C_BOLD}Start with Docker:${C_RESET}"
echo -e "  cp \"$(realpath "$OUTPUT" 2>/dev/null || echo "$OUTPUT")\" \"${REPO_ROOT}/trapster/data/trapster.conf\" && docker compose -f \"${REPO_ROOT}/docker-compose.yml\" up --build"
echo -e "${C_DIM}(or mount your generated file at /etc/trapster/trapster.conf)${C_RESET}"
