#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# PROMETHEUS – CLAUDE CODE START SCRIPT
# Version: 1.0
# Dieses Script orchestriert den autonomen Entwicklungs-Workflow.
# Wird ausschliesslich vom Core Dev getriggert.
# Usage: ./claude-code-start.sh [OPTIONEN]
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ─── Konfiguration ──────────────────────────────────────────────────────────
REPO_DIR="${PROMETHEUS_REPO:-$(pwd)}"
MEMORY_DIR="$REPO_DIR/memory"
SCRIPTS_DIR="$REPO_DIR/scripts"
LOG_FILE="$REPO_DIR/logs/claude-code-$(date +%Y%m%d-%H%M%S).log"
SECRETS_DIR="$REPO_DIR/.secrets"

# Farben für Terminal-Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ─── Hilfsfunktionen ─────────────────────────────────────────────────────────
log() { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[✗] ERROR:${NC} $1" | tee -a "$LOG_FILE"; exit 1; }
warning() { echo -e "${YELLOW}[!] WARNING:${NC} $1" | tee -a "$LOG_FILE"; }
info() { echo -e "${BLUE}[i]${NC} $1" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════${NC}"; echo -e "${BOLD}${BLUE}  $1${NC}"; echo -e "${BOLD}${BLUE}══════════════════════════════════════${NC}\n" | tee -a "$LOG_FILE"; }

# ─── Argument-Parsing ─────────────────────────────────────────────────────────
TASK=""
ACTION="run"
SPRINT=""
DRY_RUN=false

usage() {
    echo ""
    echo -e "${BOLD}PROMETHEUS – Claude Code Start Script${NC}"
    echo ""
    echo "Usage: ./claude-code-start.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --task <description>    Führe eine spezifische Task aus"
    echo "  --sprint <number>       Führe einen kompletten Sprint aus"
    echo "  --detect-blockers       Erkenne und berichte Blockaden"
    echo "  --status                Zeige aktuellen Projektstatus"
    echo "  --next                  Ermittle und führe nächste Task aus"
    echo "  --dry-run               Zeige was ausgeführt werden würde"
    echo "  --audit-pending         Liste alle ausstehenden Audits"
    echo "  --sync                  Nur GitHub sync ohne Task-Ausführung"
    echo ""
    echo "Beispiele:"
    echo "  ./claude-code-start.sh --next"
    echo "  ./claude-code-start.sh --task 'Sprint 0: Testnet Node einrichten'"
    echo "  ./claude-code-start.sh --sprint 1"
    echo "  ./claude-code-start.sh --detect-blockers"
    echo "  ./claude-code-start.sh --status"
    echo ""
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --task)         TASK="$2"; ACTION="task"; shift 2 ;;
        --sprint)       SPRINT="$2"; ACTION="sprint"; shift 2 ;;
        --detect-blockers) ACTION="detect-blockers"; shift ;;
        --status)       ACTION="status"; shift ;;
        --next)         ACTION="next"; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --audit-pending) ACTION="audit-pending"; shift ;;
        --sync)         ACTION="sync"; shift ;;
        --help|-h)      usage ;;
        *)              error "Unbekannte Option: $1. Nutze --help für Hilfe." ;;
    esac
done

# ─── Initialisierung ──────────────────────────────────────────────────────────
mkdir -p "$REPO_DIR/logs"
mkdir -p "$REPO_DIR/tmp"

echo ""
echo -e "${BOLD}${BLUE}"
echo "  ██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗███████╗██╗   ██╗███████╗"
echo "  ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝"
echo "  ██████╔╝██████╔╝██║   ██║██╔████╔██║█████╗     ██║   ███████║█████╗  ██║   ██║███████╗"
echo "  ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║   ██║╚════██║"
echo "  ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████║"
echo "  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}Autonomous Development System v1.0${NC}"
echo -e "  ${CYAN}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

# ─── Schritt 1: GitHub Sync ───────────────────────────────────────────────────
section "SCHRITT 1: GitHub Sync"

if [[ ! -d "$REPO_DIR/.git" ]]; then
    error "Kein Git-Repository gefunden in: $REPO_DIR"
fi

log "Repository: $REPO_DIR"
log "Branch: $(git -C "$REPO_DIR" branch --show-current 2>/dev/null || echo 'unbekannt')"

if [[ "$DRY_RUN" == "false" ]]; then
    log "Pulling latest changes from GitHub..."
    git -C "$REPO_DIR" pull origin main --quiet 2>/dev/null || warning "Git pull fehlgeschlagen (möglicherweise offline oder kein Remote)"
    success "GitHub sync abgeschlossen"
fi

# ─── Schritt 2: Memory Layer laden ────────────────────────────────────────────
section "SCHRITT 2: Memory Layer laden"

if [[ ! -d "$MEMORY_DIR" ]]; then
    error "Memory-Verzeichnis nicht gefunden: $MEMORY_DIR. Bitte Setup ausführen."
fi

log "Lade Memory-Dateien..."
for f in MEMO.md TODO.md STATUS.md SCHEMA.md API.md ERRORS.md SPRINTS.md AUDIT.md; do
    if [[ -f "$MEMORY_DIR/$f" ]]; then
        lines=$(wc -l < "$MEMORY_DIR/$f")
        success "  $f ($lines Zeilen)"
    else
        warning "  $f FEHLT – wird erstellt"
        touch "$MEMORY_DIR/$f"
    fi
done

# Memory in Context laden
log "Verarbeite Memory mit autodidactic.py..."
MEMORY_CONTEXT=$(python3 "$SCRIPTS_DIR/autodidactic.py" \
    --repo "$REPO_DIR" \
    --action "load_context" 2>/dev/null || echo '{"error": "autodidactic.py fehler"}')

success "Memory Layer geladen"

# ─── Schritt 3: Action ausführen ──────────────────────────────────────────────
section "SCHRITT 3: Action → $ACTION"

case "$ACTION" in

    "status")
        log "Zeige Projektstatus..."
        python3 "$SCRIPTS_DIR/autodidactic.py" \
            --repo "$REPO_DIR" \
            --action "show_status"
        exit 0
        ;;

    "detect-blockers")
        log "Erkenne Blockaden..."
        BLOCKERS=$(python3 "$SCRIPTS_DIR/autodidactic.py" \
            --repo "$REPO_DIR" \
            --action "detect_blockers")
        echo "$BLOCKERS"
        exit 0
        ;;

    "audit-pending")
        log "Ausstehende Audits:"
        grep "PENDING_AUDIT\|PENDING" "$MEMORY_DIR/AUDIT.md" || echo "Keine ausstehenden Audits."
        exit 0
        ;;

    "sync")
        success "Sync abgeschlossen."
        exit 0
        ;;

    "next")
        log "Ermittle nächste Task..."
        NEXT_TASK=$(python3 "$SCRIPTS_DIR/autodidactic.py" \
            --repo "$REPO_DIR" \
            --action "get_next_task")
        TASK=$(echo "$NEXT_TASK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('task', {}).get('task', 'Keine Task gefunden'))" 2>/dev/null || echo "Keine Task gefunden")
        log "Nächste Task: $TASK"
        ACTION="task"
        ;& # fallthrough zu "task"

    "task")
        if [[ -z "$TASK" ]]; then
            error "Keine Task angegeben. Nutze --task <beschreibung> oder --next"
        fi

        log "Task: $TASK"

        if [[ "$DRY_RUN" == "true" ]]; then
            info "DRY RUN – würde ausführen: $TASK"
            info "Kontext würde aus Memory-Layer geladen werden"
            exit 0
        fi

        # Task-Context für Claude Code sammeln
        log "Sammle Kontext für Task..."
        TASK_CONTEXT=$(python3 "$SCRIPTS_DIR/autodidactic.py" \
            --repo "$REPO_DIR" \
            --action "get_task_context" \
            --task "$TASK" 2>/dev/null || echo "")

        # Kontext in temporäre Datei speichern
        echo "$TASK_CONTEXT" > "$REPO_DIR/tmp/current_context.txt"

        # STATUS.md aktualisieren
        python3 "$SCRIPTS_DIR/autodidactic.py" \
            --repo "$REPO_DIR" \
            --action "mark_in_progress" \
            --task "$TASK" 2>/dev/null || true

        # Task an Claude Code übergeben
        log "Übergebe Task an Claude Code..."
        echo ""
        echo -e "${BOLD}${YELLOW}══ CLAUDE CODE PROMPT ══════════════════════════════════════${NC}"
        echo ""
        echo -e "${BOLD}TASK:${NC} $TASK"
        echo ""
        echo -e "${BOLD}KONTEXT (aus Memory Layer):${NC}"
        cat "$REPO_DIR/tmp/current_context.txt" 2>/dev/null | head -100
        echo ""
        echo -e "${BOLD}ANWEISUNGEN FÜR CLAUDE CODE:${NC}"
        echo "1. Lies MEMO.md für Architekturentscheidungen (KRITISCH)"
        echo "2. Lies SCHEMA.md für Datenstrukturen"
        echo "3. Lies ERRORS.md für bekannte Fehler-Muster"
        echo "4. Implementiere die Task vollständig"
        echo "5. Schreibe Tests (mind. 80% Coverage)"
        echo "6. Führe cargo fmt + cargo clippy aus (Rust)"
        echo "7. Aktualisiere STATUS.md nach Fertigstellung"
        echo "8. Erstelle AUDIT_PENDING Eintrag in AUDIT.md"
        echo "9. Committe und pushe zu GitHub"
        echo ""
        echo -e "${BOLD}${YELLOW}════════════════════════════════════════════════════════════${NC}"
        echo ""

        # Warte auf Claude Code Ausführung
        read -p "$(echo -e ${BOLD})Claude Code ausgeführt? Ergebnis eingeben (ok/fail/blocked): $(echo -e ${NC})" RESULT

        case "$RESULT" in
            "ok"|"OK"|"done"|"DONE")
                success "Task erfolgreich abgeschlossen"
                python3 "$SCRIPTS_DIR/autodidactic.py" \
                    --repo "$REPO_DIR" \
                    --action "mark_completed" \
                    --task "$TASK" \
                    --result "success" 2>/dev/null || true
                ;;
            "fail"|"FAIL"|"error"|"ERROR")
                warning "Task fehlgeschlagen"
                read -p "Fehlerbeschreibung: " ERROR_DESC
                python3 "$SCRIPTS_DIR/autodidactic.py" \
                    --repo "$REPO_DIR" \
                    --action "log_error" \
                    --task "$TASK" \
                    --error "$ERROR_DESC" 2>/dev/null || true
                ;;
            "blocked"|"BLOCKED")
                warning "Task blockiert"
                read -p "Blockade-Beschreibung: " BLOCK_DESC
                python3 "$SCRIPTS_DIR/autodidactic.py" \
                    --repo "$REPO_DIR" \
                    --action "mark_blocked" \
                    --task "$TASK" \
                    --blocker "$BLOCK_DESC" 2>/dev/null || true
                ;;
        esac
        ;;

    "sprint")
        if [[ -z "$SPRINT" ]]; then
            error "Kein Sprint angegeben. Nutze --sprint <nummer>"
        fi

        log "Starte Sprint $SPRINT..."
        SPRINT_TASKS=$(grep -A 100 "SPRINT $SPRINT:" "$MEMORY_DIR/TODO.md" | grep "^\- \[ \]" | head -20)

        if [[ -z "$SPRINT_TASKS" ]]; then
            warning "Keine offenen Tasks in Sprint $SPRINT gefunden."
            exit 0
        fi

        echo ""
        echo -e "${BOLD}Sprint $SPRINT Tasks:${NC}"
        echo "$SPRINT_TASKS"
        echo ""
        echo -e "${BOLD}${YELLOW}Starte alle Tasks in Sprint $SPRINT sequenziell.${NC}"
        echo "Für jede Task wird Claude Code getriggert."
        ;;

esac

# ─── Schritt 4: GitHub Push ───────────────────────────────────────────────────
section "SCHRITT 4: Memory Update & GitHub Push"

if [[ "$DRY_RUN" == "false" ]]; then
    log "Committe Memory-Updates..."
    git -C "$REPO_DIR" add memory/ logs/ 2>/dev/null || true
    git -C "$REPO_DIR" diff --staged --quiet || \
        git -C "$REPO_DIR" commit -m "chore: Auto-update memory layer [$(date '+%Y-%m-%d %H:%M')]" --quiet 2>/dev/null || true
    git -C "$REPO_DIR" push origin main --quiet 2>/dev/null || \
        warning "Push fehlgeschlagen – möglicherweise offline"
    success "GitHub sync abgeschlossen"
fi

# ─── Abschluss ────────────────────────────────────────────────────────────────
section "ABSCHLUSS"

echo -e "${BOLD}Status:${NC}"
python3 "$SCRIPTS_DIR/autodidactic.py" \
    --repo "$REPO_DIR" \
    --action "show_summary" 2>/dev/null || true

echo ""
echo -e "${BOLD}Nächste Schritte:${NC}"
python3 "$SCRIPTS_DIR/autodidactic.py" \
    --repo "$REPO_DIR" \
    --action "get_next_actions" 2>/dev/null || \
    echo "  → Schicke Audit-Request an Claude für fertige Module"

echo ""
success "Script beendet. Log: $LOG_FILE"
echo ""
