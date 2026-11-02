#!/bin/bash
# Drives the cells of #40's scenario matrix inside the proof container, as root, one subcommand per stage;
# run.sh calls the stages in order and restarts the container between the reboot stages.
# Every cell prints one line `cell <n>: held|FAILED: <what>`; each log lands in /proof/evidence.
set -uo pipefail

EVIDENCE=/proof/evidence
HAL_BIN=/home/tester/.local/bin/hal
UNIT_DIR=/etc/systemd/system
SYSTEM_FILES=(
    "$UNIT_DIR/cloudflared.service"
    "$UNIT_DIR/cloudflared.service.d/20-nonroot.conf"
    "$UNIT_DIR/cloudflared.service.d/30-edge-global-stop.conf"
    /etc/polkit-1/rules.d/10-edge-cloudflared-stop.rules
)
RETIRED_DROP_IN="$UNIT_DIR/cloudflared.service.d/10-root-binary.conf"
MARKER=/home/tester/.local/state/edge/global-stop
# The properties the operator's ruling „sauber ersetzen“ keeps equal; ExecStart is compared apart from its path.
SHOWN=ExecStart,Type,User,DynamicUser,LoadCredential,Environment,ProtectSystem,ProtectHome,PrivateTmp,NoNewPrivileges,TimeoutStartUSec,Restart
RETENTION_SERVICE=hal-journal-retention.service
RETENTION_TIMER=hal-journal-retention.timer
# Docker's default log driver as the proof expects it, written here once because the proof must not read what it checks.
WANTED_DRIVER=journald
DAEMON_JSON=/etc/docker/daemon.json
BACKUP_DIR=/var/backups/home-setup
DOCKER_DROP_IN_DIR="$UNIT_DIR/docker.service.d"
mkdir -p "$EVIDENCE"

verdict() {  # verdict <cell> <what> <condition>: held when the condition, a shell expression, is true
    local cell=$1 what=$2 condition=$3
    if eval "$condition"; then echo "cell $cell: held: $what"; else echo "cell $cell: FAILED: $what"; fi
    return 0
}

at_terminal() {  # at_terminal <log> <command>: as tester at a pseudo-terminal, without colour so rows match as text; the exit code is the command's
    local log=$1 command=$2
    at_coloured_terminal "$log" "export NO_COLOR=1; $command"
    return
}

at_coloured_terminal() {  # at_coloured_terminal <log> <command>: as tester at a pseudo-terminal, as a person sees it; the exit code is the command's
    local log=$1 command=$2 code=0
    /proof/terminal.exp "$command" >"$EVIDENCE/$log.log" 2>&1 || code=$?
    # 26.04's systemd profile script (profile.d/80-systemd-osc-context.sh) makes each login shell emit an OSC 3008 context sequence that no person sees; it must not sit in front of a row or glue itself to PROMPTS=.
    sed -i 's/\x1b\]3008;[^\x1b]*\x1b\\//g' "$EVIDENCE/$log.log"
    return "$code"
}

at_terminal_answering() {  # at_terminal_answering <answer: yes|no|eof|interrupt> <log> <command>: the yes prompt answered so
    local answer=$1
    shift
    PROOF_ANSWER=$answer at_terminal "$@"
    return
}

without_terminal() {  # without_terminal <log> <command>: as tester with no terminal on any end
    local log=$1 command=$2
    timeout 300 su - tester -c "$command" </dev/null >"$EVIDENCE/$log.log" 2>&1
    return
}

in_log() {
    local log=$1 text=$2
    grep -qF -- "$text" "$EVIDENCE/$log.log"
    return
}

YES_PROMPT_PATTERN='Type .*yes.* to .*: '

after_the_yes() {  # after_the_yes <log>: the output after the yes prompt; all of it when no yes was asked
    local log=$1
    awk -v pattern="$YES_PROMPT_PATTERN" '{ lines[NR] = $0 } $0 ~ pattern && !asked { asked = NR } END { for (i = asked + 1; i <= NR; i++) print lines[i] }' "$EVIDENCE/$log.log"
    return
}

before_the_yes() {  # before_the_yes <log>: the plan, the output up to the yes prompt; all of it when no yes was asked
    local log=$1
    awk -v pattern="$YES_PROMPT_PATTERN" '{ lines[NR] = $0 } $0 ~ pattern && !asked { asked = NR } END { for (i = 1; i <= (asked ? asked - 1 : NR); i++) print lines[i] }' "$EVIDENCE/$log.log"
    return
}

row_in_log() {  # row_in_log <log> <row> <event regex>: a row of hal setup's run (or of a run that asked no yes), whatever its glyph
    local log=$1 row=$2 event=$3
    after_the_yes "$log" | grep -qP -- "^  [^ ]+ $row +$event( |\\r?$)"
    return
}

plan_row_in_log() {  # plan_row_in_log <log> <row> <event regex>: a row of the plan, before the yes prompt
    local log=$1 row=$2 event=$3
    before_the_yes "$log" | grep -qP -- "^  [^ ]+ $row +$event( |\\r?$)"
    return
}

yes_asked_once() {
    local log=$1
    grep -qx 'YESES=1' "$EVIDENCE/$log.log"
    return
}

yes_never_asked() {
    local log=$1
    grep -qx 'YESES=0' "$EVIDENCE/$log.log"
    return
}

asked_once() {
    local log=$1
    grep -qx 'PROMPTS=1' "$EVIDENCE/$log.log"
    return
}

announced_before_prompt() {  # announced_before_prompt <log>: the yes prompt, then the `needs sudo` row, then the system's own password prompt
    local log=$1
    awk -v pattern="$YES_PROMPT_PATTERN" '$0 ~ pattern { asked = 1 } /^  › system +needs sudo/ && asked { announced = 1 } /\[sudo[^]]*\] [Pp]ass/ && announced { found = 1 } END { exit !found }' "$EVIDENCE/$log.log"
    return
}

snapshot() {
    find "$UNIT_DIR" /etc/polkit-1/rules.d -path '*cloudflared*' -type f -exec sha256sum {} + 2>/dev/null | sort
    return
}

# What a declined or refused `hal setup` must leave alone beyond the system files: the user units, the tool installs (uv's
# receipts), the hook files and the global git config, the secrets directory and the Docker settings.
home_snapshot() {
    snapshot
    sha256sum /home/tester/.gitconfig /etc/docker/daemon.json 2>&1
    find /home/tester/.config/systemd /home/tester/.local/share/home /home/tester/.local/share/quality /home/tester/.secrets /home/tester/.local/share/uv/tools /etc/docker /etc/systemd/system/docker.service.d \
        -maxdepth 3 -printf '%p %y %s %T@\n' 2>&1 | sort
    return
}

ANSIBLE_CALL_LOG=/proof/ansible-calls.log
ANSIBLE_PLAYBOOK=/home/tester/.local/bin/ansible-playbook

ansible_calls_logged() {  # ansible_calls_logged <on|off>: a wrapper that logs every call of the tester's ansible-playbook and runs the real one
    local switch=$1
    if [[ $switch == on ]]; then
        : >"$ANSIBLE_CALL_LOG"
        mv "$ANSIBLE_PLAYBOOK" "$ANSIBLE_PLAYBOOK.real"
        printf '#!/bin/sh\necho "$*" >>%s\nexec %s.real "$@"\n' "$ANSIBLE_CALL_LOG" "$ANSIBLE_PLAYBOOK" >"$ANSIBLE_PLAYBOOK"
        chmod 755 "$ANSIBLE_PLAYBOOK"
    else
        mv -f "$ANSIBLE_PLAYBOOK.real" "$ANSIBLE_PLAYBOOK"
    fi
    return
}

as_tester() {
    runuser -u tester -- "$@"
    return
}

refused() {  # refused <unit> <command...>: polkit says no, for a unit that is loaded; "not found" is no refusal
    local unit=$1 said
    shift
    [[ $(systemctl show "$unit" -p LoadState --value) == loaded ]] || return 1
    said=$("$@" 2>&1) && return 1
    echo "$said" >>"$EVIDENCE/polkit.log"
    [[ $said == *"Interactive authentication required"* || $said == *"Access denied"* ]]
    return
}

all_exist() {
    local file
    for file in "$@"; do [[ -f $file ]] || return 1; done
    return 0
}

install_home() {  # the wheel, and the user manager `hal setup`'s user-units step talks to, running without a login
    loginctl enable-linger tester
    timeout 60 bash -c 'until systemctl is-active --quiet "user@$(id -u tester).service"; do sleep 1; done'
    su - tester -c "uv tool install /proof/*.whl" >"$EVIDENCE/install.log" 2>&1
    plant_stub_hal
    plant_fake_secrets >>"$EVIDENCE/install.log" 2>&1
    return
}

# The units' ExecStart is ~/srv/hal/.venv/bin/hal, which the proof's home has no venv for: a timer that fires inside the
# mail cells would fail its unit and change what `hal check` finds. A hal that exits 0 lets every such unit end clean,
# where the real one would write the remembered set and could mail the sink.
plant_stub_hal() {
    local bin=/home/tester/srv/hal/.venv/bin
    install -d -o tester -g tester "$bin/.." "$bin"
    printf '#!/bin/sh\nexit 0\n' >"$bin/hal"
    chown tester:tester "$bin/hal"
    chmod 755 "$bin/hal"
    return
}

# `hal setup` ends with the secrets step, which would walk the wizard at the cells' terminal for every secret the
# packaged manifest names. The tester's home therefore holds a fake file for each one, never a real secret, and the
# secrets cell takes one away and puts it back.
plant_fake_secrets() {  # plant_fake_secrets [drop]: a fake file for every live entry of the manifest; with `drop`, the first is taken away again and its name printed
    local python
    python=$(head -n 1 "$HAL_BIN" | sed 's/^#!//')
    cat >/proof/plant_secrets.py <<'PYTHON'
import sys
from pathlib import Path

from hal.workstation import secrets_view
from hal.workstation.tunnel_config import with_tunnel_id

home = Path.home()
live = [entry for entry in secrets_view.load_manifest(secrets_view.MANIFEST_PATH) if not entry.retired]
places = [home / str(with_tunnel_id(pattern)).replace("*", "fake") for entry in live for pattern in entry.paths]
for path in places:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("proof-fake-secret")
    path.chmod(0o600)
for directory in [home / ".secrets", *(home / ".secrets").rglob("*")]:
    if directory.is_dir():
        directory.chmod(0o700)
if sys.argv[1:] == ["drop"]:
    for pattern in live[0].paths:
        (home / str(with_tunnel_id(pattern)).replace("*", "fake")).unlink()
    print(live[0].name)
PYTHON
    su - tester -c "$python -I /proof/plant_secrets.py $*"
    return
}

# Today's PC, frozen literally, never derived from /proof/tunnel, so a changed hardening setting in edge's files shows
# as a difference. The non-ExecStart lines come from edge's EFFECTIVE_UNIT_WITHOUT_EXEC_START (tests/test_stack_tunnel_files.py,
# tunnel id as @TUNNEL_ID@); the ExecStart lines come from the head's read-only `systemctl cat cloudflared.service` of
# 18.10.2026. The effective ExecStart is the one `10-root-binary.conf` sets; the base unit's is the operator's ~/bin one.
write_todays_unit() {
    local id
    id=$(sed -n 's/^tunnel: //p' /etc/cloudflared/config.yml)
    mkdir -p "$UNIT_DIR/cloudflared.service.d"
    cat >"$UNIT_DIR/cloudflared.service" <<'UNIT'
[Unit]
Description=cloudflared
After=network-online.target
Wants=network-online.target

[Service]
TimeoutStartSec=15
Type=notify
ExecStart=/home/tester/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
UNIT
    cat >"$RETIRED_DROP_IN" <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run
UNIT
    sed "s/@TUNNEL_ID@/$id/" >"$UNIT_DIR/cloudflared.service.d/20-nonroot.conf" <<'UNIT'
[Service]
DynamicUser=yes
LoadCredential=tunnel.json:/etc/cloudflared/@TUNNEL_ID@.json
Environment=TUNNEL_CRED_FILE=%d/tunnel.json
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
UNIT
    return
}

shown_without_exec_start() {
    systemctl show cloudflared -p "$SHOWN" | grep -v '^ExecStart='
    return
}

exec_start_arguments() {  # the arguments of ExecStart, without the path of the binary, which is the one permitted change
    systemctl show cloudflared -p ExecStart --value | sed -n 's/.*argv\[\]=[^ ]* \(.*\) ; ignore_errors=.*/\1/p'
    return
}

prepare_today() {
    write_todays_unit
    systemctl daemon-reload
    shown_without_exec_start >"$EVIDENCE/show-before.txt"
    exec_start_arguments >"$EVIDENCE/exec-start-before.txt"
    systemctl show cloudflared -p InvocationID,ActiveState >"$EVIDENCE/state-before.txt"
    return
}

cell_2() {
    local code
    at_terminal cell2 "$HAL_BIN setup"
    code=$?
    shown_without_exec_start >"$EVIDENCE/show-after.txt"
    exec_start_arguments >"$EVIDENCE/exec-start-after.txt"
    systemctl show cloudflared -p InvocationID,ActiveState >"$EVIDENCE/state-after.txt"
    verdict 2 "apply exits 0" '[ $code -eq 0 ]'
    verdict 2 "the recorded arguments of ExecStart were there before" '[ -s "$EVIDENCE/exec-start-before.txt" ]'
    verdict 2 "systemctl show is equal apart from the ExecStart path" \
        'diff "$EVIDENCE/show-before.txt" "$EVIDENCE/show-after.txt" && diff "$EVIDENCE/exec-start-before.txt" "$EVIDENCE/exec-start-after.txt"'
    verdict 2 "10-root-binary.conf is gone" '[ ! -e "$RETIRED_DROP_IN" ]'
    verdict 2 "nothing started or restarted" 'diff "$EVIDENCE/state-before.txt" "$EVIDENCE/state-after.txt"'
    verdict 2 "the backups are outside $UNIT_DIR" '[ -n "$(find /var/backups/home-setup -name 10-root-binary.conf)" ]'
    return
}

cell_11() {
    local dry apply before
    before=$(home_snapshot)
    without_terminal cell11-dry "$HAL_BIN setup --dry-run"
    dry=$?
    verdict 11 "a dry run without a terminal says not checked, exit 0" \
        '[ $dry -eq 0 ] && row_in_log cell11-dry system "not checked" && in_log cell11-dry "needs sudo at a terminal"'
    without_terminal cell11-apply "$HAL_BIN setup"
    apply=$?
    verdict 11 "setup without a terminal prints the plan, refuses with exit 4 and runs no step" \
        '[ $apply -eq 4 ] && plan_row_in_log cell11-apply system "not checked" && in_log cell11-apply "setup asks yes at a terminal · nothing changed" &&
         [ "$(home_snapshot)" = "$before" ] && [ -z "$(su - tester -c "git config --global --get core.hooksPath")" ]'
    verdict 11 "setup without a terminal prints no needs sudo announcement" \
        '! grep -q "^  › system  *needs sudo" "$EVIDENCE/cell11-apply.log"'
    return
}

cell_12() {
    cell_12_without_a_tunnel_id missing '/^tunnel:/d'
    cell_12_without_a_tunnel_id empty 's/^tunnel:.*/tunnel:/'
    return
}

cell_12_without_a_tunnel_id() {  # <case> <sed edit of config.yml>: the `tunnel:` line gone, or left without a value
    local case_name=$1 edit=$2 log="cell12-$1" before code
    before=$(snapshot)
    cp /etc/cloudflared/config.yml /proof/config.yml.saved
    sed -i "$edit" /etc/cloudflared/config.yml
    at_terminal "$log" "$HAL_BIN setup"
    code=$?
    cp /proof/config.yml.saved /etc/cloudflared/config.yml
    verdict 12 "apply fails loudly when the tunnel id is $case_name" '[ $code -eq 3 ] && in_log "$log" "names no \`tunnel:\`"'
    verdict 12 "nothing is half-written when the tunnel id is $case_name" '[ "$before" = "$(snapshot)" ]'
    return
}

cell_13() {  # cell 12 has activated the hook already, so it is undone here for the activation to run again
    local code
    su - tester -c "git config --global --unset core.hooksPath"
    PROOF_PASSWORD="not-the-password" at_terminal cell13 "$HAL_BIN setup"
    code=$?
    verdict 13 "a wrong password fails the system step alone, exit 3" \
        '[ $code -eq 3 ] && row_in_log cell13 "commit hook" changed && row_in_log cell13 system failed'
    verdict 13 "the commit hook is active" '[ -n "$(su - tester -c "git config --global --get core.hooksPath")" ]'
    return
}

cell_10() {  # the lists are fresh as on the PC: a dry run cannot update them, and the image ships them empty
    local code
    apt-get update >"$EVIDENCE/cell10-apt-update.log" 2>&1
    at_terminal cell10 "$HAL_BIN setup --dry-run"
    code=$?
    verdict 10 "a dry run at a terminal asks once for sudo" '[ $code -eq 0 ] && asked_once cell10'
    verdict T1 "the dry run shows the units in its diff and starts nothing" \
        'in_log cell10 "hal-journal-retention.timer" && ! systemctl cat "$RETENTION_TIMER" >/dev/null 2>&1'
    verdict 10 "it shows would change, with the diff" 'row_in_log cell10 system "will change" && grep -q "^+++ " "$EVIDENCE/cell10.log"'
    verdict DK4 "the dry run on a Docker still on json-file shows the log-driver line and the restart as changes, and writes nothing" \
        'in_log cell10 "+    \"log-driver\": \"journald\"" && grep -A2 "TASK \[Restart Docker\]" "$EVIDENCE/cell10.log" | grep -q "^changed:" && [ ! -e "$DAEMON_JSON" ]'
    at_coloured_terminal cell10-colour "export TERM=xterm; $HAL_BIN setup --dry-run"
    verdict C1 "a dry run at a terminal colours its rows and its verdict; the run with NO_COLOR above has no escape code" \
        'grep -qP "^  \x1b\[[0-9;]+m\S+\x1b\[0m system " "$EVIDENCE/cell10-colour.log" && grep -qP "^\x1b\[1;[0-9;]+m\S+ setup plan" "$EVIDENCE/cell10-colour.log" && ! grep -qP "\x1b" "$EVIDENCE/cell10.log"'
    return
}

cell_1() {
    local code
    at_terminal cell1 "$HAL_BIN setup"
    code=$?
    verdict 1 "apply exits 0 after one prompt" '[ $code -eq 0 ] && asked_once cell1 && row_in_log cell1 system changed'
    verdict 1 "the apply announces needs sudo once, before the system's password prompt" \
        '[ "$(grep -c "^  › system  *needs sudo" "$EVIDENCE/cell1.log")" -eq 1 ] && announced_before_prompt cell1'
    verdict 1 "the four files are root-owned, mode 644" '[ "$(stat -c "%U %a" "${SYSTEM_FILES[@]}" | sort -u)" = "root 644" ]'
    verdict 1 "every placeholder is filled" 'all_exist "${SYSTEM_FILES[@]}" && ! grep -lE "@[A-Z_]+@" "${SYSTEM_FILES[@]}"'
    verdict 1 "systemd-analyze verify passes" 'systemd-analyze verify cloudflared.service >"$EVIDENCE/verify.log" 2>&1'
    verdict D1 "the apply installed msmtp and ca-certificates, and msmtp-mta is not there" \
        'dpkg -s msmtp ca-certificates >/dev/null 2>&1 && ! dpkg -s msmtp-mta >/dev/null 2>&1'
    verdict DK2 "with no daemon.json the apply created exactly the journal as default, root-owned, mode 644" \
        'daemon_json_is "{\"log-driver\": \"$WANTED_DRIVER\"}" && [ "$(stat -c "%U %a" "$DAEMON_JSON")" = "root 644" ]'
    verdict DK4 "after the first apply docker info says the journal" '[ "$(docker_default_driver)" = "$WANTED_DRIVER" ]'
    docker_started_at >"$EVIDENCE/dk4-started-after-cell1.txt"
    return
}

cell_9() {
    local code
    at_terminal cell9 "$HAL_BIN setup"
    code=$?
    verdict DK4 "a second apply restarts nothing: Docker's start time is unchanged" \
        '[ "$(docker_started_at)" = "$(cat "$EVIDENCE/dk4-started-after-cell1.txt")" ]'
    verdict 9 "a second apply: Ansible reports changed=0, System unchanged" \
        '[ $code -eq 0 ] && grep -qE "changed=0 " "$EVIDENCE/cell9.log" && row_in_log cell9 system unchanged'
    verdict 9 "Ansible left nothing in the home" '[ ! -e /home/tester/.ansible ]'
    verdict D2 "a second apply installs nothing: changed=0" '[ $code -eq 0 ] && grep -qE "changed=0 " "$EVIDENCE/cell9.log"'
    return
}

cell_s1() {  # the secrets step: verified with every fake secret in place; the dry run names the one taken away and writes nothing
    local code dropped
    verdict S1 "every secret in place: the secrets step is unchanged" 'row_in_log cell9 secrets complete'
    dropped=$(plant_fake_secrets drop)
    without_terminal cell-s1 "$HAL_BIN setup --dry-run"
    code=$?
    verdict S1 "a dry run names the missing secret $dropped and exits 0" \
        '[ $code -eq 0 ] && row_in_log cell-s1 secrets missing && in_log cell-s1 "$dropped"'
    plant_fake_secrets >/dev/null
    return
}

# The yes cells (Y1-Y8). A declined, interrupted or refused `hal setup` changes nothing: not the system files, the user
# units, the tool installs, the hook files, the git config, the secrets directory or Docker, and it never calls Ansible
# (the wrapper's log stays empty, which a cached sudo ticket could not hide).
reopen_the_hook() {  # the hook files and core.hooksPath gone, so the commit hook row is open again
    su - tester -c "git config --global --unset core.hooksPath; rm -rf /home/tester/.local/share/home/git-hooks"
    return
}

cell_y_not_run() {  # cell_y_not_run <cell> <answer> <exit code> <error line, or "" for none>: the answer at the yes prompt runs nothing
    local cell=$1 answer=$2 expected=$3 error=$4 log="y-${1,,}" code before after
    reopen_the_hook
    ansible_calls_logged on
    before=$(home_snapshot)
    at_terminal_answering "$answer" "$log" "$HAL_BIN setup"
    code=$?
    after=$(home_snapshot)
    ansible_calls_logged off
    verdict "$cell" "answer '$answer': exit $expected, one yes asked, no sudo prompt, no Ansible call, nothing changed" \
        '[ $code -eq $expected ] && yes_asked_once "$log" && grep -qx "PROMPTS=0" "$EVIDENCE/$log.log" && [ ! -s "$ANSIBLE_CALL_LOG" ] && [ "$before" = "$after" ] &&
         plan_row_in_log "$log" system "not checked" && ! grep -q "^  › system  *needs sudo" "$EVIDENCE/$log.log"'
    if [[ -n $error ]]; then
        verdict "$cell" "the one error line is '$error', and no next line" \
            'in_log "$log" "$error" && ! grep -q "^next:" "$EVIDENCE/$log.log"'
    else
        verdict "$cell" "Ctrl-C prints no error line" '! grep -q "^error:" "$EVIDENCE/$log.log"'
    fi
    return
}

cell_y5_apply_is_gone() {
    local code before
    before=$(home_snapshot)
    without_terminal y5 "$HAL_BIN setup --apply"
    code=$?
    verdict Y5 "--apply exits 2 with the usage pair and nothing ran" \
        '[ $code -eq 2 ] && in_log y5 "error: unrecognized arguments: --apply" && in_log y5 "next: hal setup --help" && [ "$before" = "$(home_snapshot)" ]'
    verdict Y5 "--apply prints nothing on stdout" '[ -z "$(su - tester -c "$HAL_BIN setup --apply" 2>/dev/null </dev/null)" ]'
    return
}

cell_y8_the_wizard_after_the_yes() {  # the first manifest entry is a token: the page opens (BROWSER=true, no DISPLAY), the empty paste skips it
    local code dropped
    dropped=$(plant_fake_secrets drop)
    at_terminal y8 "unset DISPLAY; export BROWSER=true; $HAL_BIN setup"
    code=$?
    verdict Y8 "the plan names the missing secret, the yes comes before the wizard, an empty paste stops setup: exit 3, no file" \
        '[ $code -eq 3 ] && yes_asked_once y8 && plan_row_in_log y8 secrets missing && in_log y8 "$dropped" && in_log y8 "setup stopped at secrets · 1 secret still open" && [ ! -e "/home/tester/.secrets/$dropped" ]'
    plant_fake_secrets >/dev/null
    return
}

cell_y1_one_yes_then_one_sudo() {
    local code
    reopen_the_hook
    at_terminal y1 "$HAL_BIN setup"
    code=$?
    verdict Y1 "one yes, one sudo: the plan has no sudo prompt, the yes comes before the announcement and the announcement before sudo's prompt" \
        '[ $code -eq 0 ] && yes_asked_once y1 && asked_once y1 && announced_before_prompt y1 && ! before_the_yes y1 | grep -q "\[sudo" &&
         plan_row_in_log y1 "commit hook" "will change" && row_in_log y1 "commit hook" changed && in_log y1 "✓ setup done"'
    return
}

cells_yes() {  # the declines first, then the yes that converges the machine again
    cell_y_not_run Y2 no 1 "error: aborted, nothing changed"
    cell_y_not_run Y3 eof 1 "error: aborted, nothing changed"
    cell_y_not_run Y4 interrupt 130 ""
    cell_y_not_run Y6 Yes 1 "error: aborted, nothing changed"
    cell_y5_apply_is_gone
    cell_y8_the_wizard_after_the_yes
    cell_y1_one_yes_then_one_sudo
    return
}

# The journal retention cells (T1-T5b; T6 is a unit test). They run after the cloudflared cells in
# the stage that has applied the playbook once, and T3 ends by taking its proof-only override away again.
retention_active_journal_survives() {
    local file
    file=$(find /run/log/journal /var/log/journal -name system.journal 2>/dev/null | head -n 1)
    [[ -n $file ]]
    return
}

# A planted file gets a sequence id of its own: journalctl orders two files of one id by sequence
# number, which would contradict their ages.
plant_archive() {  # plant_archive <directory> <age in seconds> <suffix>: a real archive, named as if its oldest entry were that old
    local directory=$1 age=$2 suffix=$3 microseconds name
    microseconds=$(( ($(date +%s) - age) * 1000000 ))
    if [[ $suffix == journal ]]; then
        name=$(printf 'system@%032x-%016x-%016x.journal' "$microseconds" 1 "$microseconds")
    else
        name=$(printf 'system@%016x-%016x.journal~' "$microseconds" 1)
    fi
    cp "$directory/planted-source" "$directory/$name"
    echo "$directory/$name"
    return
}

cell_t1() {
    verdict T1 "both units show 28d and daily in systemctl cat" \
        'systemctl cat "$RETENTION_SERVICE" "$RETENTION_TIMER" >"$EVIDENCE/t1-cat.txt" && grep -qF -- "--rotate --vacuum-time=28d" "$EVIDENCE/t1-cat.txt" && grep -qx "OnCalendar=daily" "$EVIDENCE/t1-cat.txt" && grep -qx "Persistent=true" "$EVIDENCE/t1-cat.txt"'
    verdict T1 "the timer is enabled and list-timers shows a next run" \
        'systemctl list-timers "$RETENTION_TIMER" --no-pager >"$EVIDENCE/t1-timers.txt"; [[ $(systemctl is-enabled "$RETENTION_TIMER") == enabled ]] && grep -q "$RETENTION_TIMER" "$EVIDENCE/t1-timers.txt" && ! grep -q " n/a " "$EVIDENCE/t1-timers.txt"'
    verdict T1 "the units are root-owned, mode 644" \
        '[ "$(stat -c "%U %a" "$UNIT_DIR/$RETENTION_SERVICE" "$UNIT_DIR/$RETENTION_TIMER" | sort -u)" = "root 644" ]'
    return
}

cell_t2() {
    local directory=/var/log/journal/$(cat /etc/machine-id) old kept disposed
    mkdir -p "$directory"
    logger -t proof-planted "a line for the planted archives"
    journalctl --rotate
    cp "$(ls -t "$directory"/system@*.journal | head -n 1)" "$directory/planted-source"
    old=$(plant_archive "$directory" $((28 * 86400 + 3600)) journal)
    kept=$(plant_archive "$directory" $((27 * 86400)) journal)
    disposed=$(plant_archive "$directory" $((29 * 86400)) disposed)
    rm "$directory/planted-source"
    ls -la --time-style=full-iso "$directory" >"$EVIDENCE/t2-before.txt"
    systemctl start "$RETENTION_SERVICE" >"$EVIDENCE/t2-run.log" 2>&1
    ls -la --time-style=full-iso "$directory" >"$EVIDENCE/t2-after.txt"
    journalctl --no-pager -u "$RETENTION_SERVICE" >"$EVIDENCE/t2-service.txt" 2>&1
    verdict T2 "one run deletes the archive at 28 d + 1 h" '[ ! -e "$old" ]'
    verdict T2 "one run deletes the .journal~ at 29 d" '[ ! -e "$disposed" ]'
    verdict T2 "it keeps the archive at 27 d and the active file" '[ -e "$kept" ] && retention_active_journal_survives'
    rm -f "$kept"
    return
}

seconds_since_epoch() {  # seconds_since_epoch <systemd timestamp>: fails on an empty or unparsable one
    local timestamp=$1
    [[ -n $timestamp ]] || return 1
    LC_ALL=C date -d "$timestamp" +%s
    return
}

wait_for_new_invocation() {  # wait_for_new_invocation <old id>: the service's new, non-empty id, or failure after 70 s
    local old=$1 current deadline=$((SECONDS + 70))
    while ((SECONDS < deadline)); do
        current=$(systemctl show "$RETENTION_SERVICE" -p InvocationID --value) || return 1
        if [[ -n $current && $current != "$old" ]]; then
            echo "$current"
            return 0
        fi
        sleep 1
    done
    return 1
}

cell_t4() {
    local before restarted invocation exit_timestamp activated
    before=$(systemctl show "$RETENTION_SERVICE" -p InvocationID --value) || before=unobserved
    touch -d '2 days ago' "/var/lib/systemd/timers/stamp-$RETENTION_TIMER"
    restarted=$(date +%s)
    systemctl restart "$RETENTION_TIMER"
    invocation=$(wait_for_new_invocation "$before")
    exit_timestamp=$(systemctl show "$RETENTION_SERVICE" -p InactiveExitTimestamp --value) || exit_timestamp=
    activated=$(seconds_since_epoch "$exit_timestamp")
    verdict T4 "two days after its last run the service runs within a minute of the timer's start" \
        '[[ $before != unobserved && -n $invocation && -n $activated ]] && ((activated >= restarted && activated - restarted <= 60))'
    return
}

cell_t5() {
    local first second
    cp "$UNIT_DIR/$RETENTION_SERVICE" "$UNIT_DIR/$RETENTION_TIMER" /proof/
    systemctl disable --now "$RETENTION_TIMER" >/dev/null 2>&1
    rm -f "$UNIT_DIR/$RETENTION_SERVICE" "$UNIT_DIR/$RETENTION_TIMER"
    systemctl daemon-reload
    cp "/proof/$RETENTION_SERVICE" "/proof/$RETENTION_TIMER" "$UNIT_DIR/"
    verdict T5 "the interrupted state is set: units on disk, the timer neither enabled nor active" \
        '[ "$(systemctl is-enabled $RETENTION_TIMER 2>&1)" != enabled ] && [ "$(systemctl is-active $RETENTION_TIMER)" != active ]'
    at_terminal t5-first "$HAL_BIN setup"
    first=$?
    journalctl --unit docker --no-pager --lines 80 >"$EVIDENCE/t5-docker-unit.txt" 2>&1
    verdict T5 "apply converges: the timer is enabled and active" \
        '[ $first -eq 0 ] && [ "$(systemctl is-enabled $RETENTION_TIMER)" = enabled ] && [ "$(systemctl is-active $RETENTION_TIMER)" = active ]'
    at_terminal t5-second "$HAL_BIN setup"
    second=$?
    verdict T5 "a second run reports changed=0" '[ $second -eq 0 ] && grep -qE "changed=0 " "$EVIDENCE/t5-second.log" && row_in_log t5-second system unchanged'
    return
}

cell_t5b() {  # the timer is enabled and the service unit on disk is newer than the one systemd loaded
    local first second
    cp "$UNIT_DIR/$RETENTION_SERVICE" "/proof/t5b-original.service"
    sed -i 's/--vacuum-time=28d/--vacuum-time=5d/' "$UNIT_DIR/$RETENTION_SERVICE"
    systemctl daemon-reload
    cp "/proof/t5b-original.service" "$UNIT_DIR/$RETENTION_SERVICE"
    verdict T5b "the stale state is set: the timer is enabled, systemd runs 5d and needs a reload" \
        '[ "$(systemctl is-enabled $RETENTION_TIMER)" = enabled ] && [ "$(systemctl show $RETENTION_SERVICE -p NeedDaemonReload --value)" = yes ] && systemctl show $RETENTION_SERVICE -p ExecStart --value | grep -qF -- "--vacuum-time=5d"'
    at_terminal t5b-first "$HAL_BIN setup"
    first=$?
    verdict T5b "apply reloads without changing a file: systemd needs no reload and runs 28d" \
        '[ $first -eq 0 ] && grep -qE "changed=0 " "$EVIDENCE/t5b-first.log" && [ "$(systemctl show $RETENTION_SERVICE -p NeedDaemonReload --value)" = no ] && systemctl show $RETENTION_SERVICE -p ExecStart --value | grep -qF -- "--vacuum-time=28d"'
    at_terminal t5b-second "$HAL_BIN setup"
    second=$?
    verdict T5b "a repeat reports changed=0" '[ $second -eq 0 ] && grep -qE "changed=0 " "$EVIDENCE/t5b-second.log" && row_in_log t5b-second system unchanged'
    return
}

# Prints present or absent when the journal answered, and fails when the observation itself failed. Reading
# writes nothing, so the journal stays quiet. systemd 255 exits 1 and prints nothing when no entry matches,
# so absence is that silent exit 1 with the journal's header and boot list still readable; any other
# outcome is a failed observation, never absence.
observe_journal_line() {  # observe_journal_line <text>
    local text=$1 output status=0
    journalctl --header >/dev/null && journalctl --list-boots >/dev/null || return 1
    output=$(journalctl --no-pager -o cat --grep "$text" 2>&1) || status=$?
    if ((status == 0)) && grep -qF -- "$text" <<<"$output"; then
        echo present
    elif ((status == 1)) && [[ -z $output ]]; then
        echo absent
    else
        return 1
    fi
    return 0
}

wait_until_journal_line_is_there() {  # wait_until_journal_line_is_there <text>: present within 30 s, by a successful query
    local text=$1 deadline=$((SECONDS + 30))
    while ((SECONDS < deadline)); do
        [[ $(observe_journal_line "$text") == present ]] && return 0
        sleep 1
    done
    return 1
}

wait_until_journal_line_is_gone() {  # wait_until_journal_line_is_gone <text>: absent within 190 s, by a successful query
    local text=$1 deadline=$((SECONDS + 190))
    while ((SECONDS < deadline)); do
        [[ $(observe_journal_line "$text") == absent ]] && return 0
        sleep 5
    done
    return 1
}

cell_t3() {
    local marker=retention-marker-$$ override_service="$UNIT_DIR/$RETENTION_SERVICE.d" override_timer="$UNIT_DIR/$RETENTION_TIMER.d"
    mkdir -p "$override_service" "$override_timer"
    printf '%s\n' '[Service]' 'ExecStart=' 'ExecStart=/usr/bin/journalctl --rotate --vacuum-time=2min' >"$override_service/proof.conf"
    printf '%s\n' '[Timer]' 'OnCalendar=' 'OnCalendar=minutely' >"$override_timer/proof.conf"
    systemctl daemon-reload && systemctl restart "$RETENTION_TIMER"
    logger -t proof-marker "$marker"
    verdict T3 "the marker line is in the journal before the run" 'wait_until_journal_line_is_there "$marker"'
    verdict T3 "a quiet journal loses the marker within 3 min 10 s, seen by a query that succeeded" \
        'wait_until_journal_line_is_gone "$marker"'
    rm -rf "$override_service" "$override_timer"
    systemctl daemon-reload
    systemctl restart "$RETENTION_TIMER"
    return
}

cells_retention() {
    cell_t1
    cell_t4
    cell_t2
    cell_t5
    cell_t5b
    cell_t3
    return
}

cells_polkit() {
    : >"$EVIDENCE/polkit.log"
    systemctl start cloudflared || true
    verdict 3 "tester may stop cloudflared" 'as_tester systemctl --no-ask-password stop cloudflared'
    local verb
    for verb in start restart kill; do
        systemctl start cloudflared || true  # kill needs a unit systemd still holds, and stop (cell 3) let it go
        verdict 4 "tester may not $verb cloudflared" 'refused cloudflared as_tester systemctl --no-ask-password "$verb" cloudflared'
    done
    verdict 5 "tester may not stop another unit" 'refused proof-other.service as_tester systemctl --no-ask-password stop proof-other.service'
    systemctl start cloudflared || true
    verdict 6 "another user may not stop cloudflared" 'refused cloudflared runuser -u bystander -- systemctl --no-ask-password stop cloudflared'
    systemctl stop cloudflared
    return
}

marker_on() {  # a failure is a cell 7 line, never an exit: the reboot stages must still run
    local message
    if message=$(as_tester mkdir -p "$(dirname "$MARKER")" && as_tester touch "$MARKER" && systemctl enable cloudflared 2>&1); then
        echo "cell 7: held: the marker is set and cloudflared is enabled"
    else
        echo "cell 7: FAILED: the marker could not be set and cloudflared enabled: $message"
    fi
    return 0
}

marker_off() {
    rm -f "$MARKER"
    return
}

this_boot_journal() {  # the journal is shared across `docker restart` (one boot id), so a boot is told by PID 1's start
    local booted_at
    booted_at=$(date -d "$(systemctl show --value --property UserspaceTimestamp)" '+%F %T')
    journalctl --unit cloudflared --since "$booted_at" --no-pager
    return
}

boot_diagnosis() {  # boot_diagnosis <log>: what systemd made of cloudflared at this boot, for a cell that did not hold
    local log=$1
    {
        ls -la "$(dirname "$MARKER")"
        systemctl is-enabled cloudflared
        systemctl status cloudflared --no-pager
        this_boot_journal
    } >"$EVIDENCE/$log.txt" 2>&1
    return 0
}

# A cell counts only on a line systemd wrote at that boot: an inactive unit is also what one never looked at.
cell_7() {
    boot_diagnosis boot-7
    systemctl show cloudflared -p ActiveState >"$EVIDENCE/cell7.txt"
    verdict 7 "with the marker the unit is condition-skipped after a reboot" \
        'grep -qx ActiveState=inactive "$EVIDENCE/cell7.txt" && grep -q "skipped, unmet condition check ConditionPathExists=!" "$EVIDENCE/boot-7.txt"'
    return
}

cell_8() {
    boot_diagnosis boot-8
    verdict 8 "without the marker the unit tries to start after a reboot" \
        'grep -q "Starting cloudflared.service" "$EVIDENCE/boot-8.txt" && ! grep -q "unmet condition check" "$EVIDENCE/boot-8.txt"'
    return
}

# The agents' account (#331, matrix A1; its cells are named A1-<n> so they never meet the cells of #40). Cell 10, a revert,
# is not driven: it keeps the user and its home, and no revert exists to run.
AGENT_HOME=/home/agent
DOCKER_SOCKET=/run/docker.sock
OPERATORS_SKIP="the operator's step"

run_as() {  # run_as <user> <log> <command...>: with that user's own HOME and runtime directory, no terminal, no sudo
    local user=$1 log=$2
    shift 2
    timeout 1800 runuser -u "$user" -- env -i HOME="/home/$user" XDG_RUNTIME_DIR="/run/user/$(id -u "$user")" LC_ALL=C.UTF-8 \
        PATH="/usr/local/bin:/usr/bin:/bin:/home/$user/.local/bin" "$@" </dev/null >"$EVIDENCE/$log.log" 2>&1
    return
}

agent_world() {  # everything the play may write about the account, as one comparable text
    getent passwd agent
    getent group agent
    getent shadow agent
    id -Gn agent
    stat -c '%U:%G %a' "$AGENT_HOME" 2>&1
    cat /etc/subuid /etc/subgid /etc/cron.deny 2>&1
    ls /var/lib/systemd/linger 2>&1
    snapshot
    return 0
}

agent_is_dormant() {  # one account, one regular id for uid and gid, its own group, locked, nologin, a closed home, no subids, no linger, denied cron and nothing else denied
    [[ $(id -u agent) -ge 1000 && $(id -u agent) == "$(id -g agent)" && $(getent group agent | cut -d: -f3) == "$(id -g agent)" ]] &&
        [[ $(getent passwd agent | cut -d: -f7) == /usr/sbin/nologin ]] &&
        [[ $(id -Gn agent) == agent ]] &&
        [[ $(getent shadow agent | cut -d: -f2 | cut -c1) == '!' ]] &&
        [[ $(stat -c '%U:%G %a' "$AGENT_HOME") == 'agent:agent 700' ]] &&
        ! grep -qE '^agent:' /etc/subuid /etc/subgid &&
        [[ $(cat /etc/cron.deny) == agent ]] &&
        [[ ! -e /var/lib/systemd/linger/agent ]]
    return
}

put_operator_in_docker_group() {  # the engine ships docker.socket as root:docker 660; the operator is in the group, the agents' account is not
    usermod --append --groups docker tester
    systemctl start docker.socket
    return
}

connects_to_docker() {  # connects_to_docker <user>
    local user=$1
    run_as "$user" "docker-$user" python3 -c "import socket; socket.socket(socket.AF_UNIX).connect('$DOCKER_SOCKET')"
    return
}

agent_is_refused() {  # what the account may not reach, each against a control that shows the thing is there and reachable by its owner
    local secret=/home/tester/.secrets/proof-a1
    [[ $(stat -c %a /home/tester) -le 750 ]] || return 1
    as_tester mkdir -p "$(dirname "$secret")" && as_tester touch "$secret" && as_tester cat "$secret" || return 1
    connects_to_docker tester || return 1
    ! run_as agent a1-ls ls /home/tester &&
        ! run_as agent a1-cat cat "$secret" &&
        ! run_as agent a1-sudo sudo -n true &&
        ! connects_to_docker agent &&
        ! su - agent -c true >"$EVIDENCE/a1-su.log" 2>&1 &&
        grep -q 'not available' "$EVIDENCE/a1-su.log"
    return
}

cell_a1_1() {
    verdict A1-1 "the apply created agent: own group, locked, nologin, home 0700, no subids, cron.deny, no linger" agent_is_dormant
    A1_WORLD_AFTER_CREATION=$(agent_world)
    return
}

cell_a1_2() {  # runs after the second apply of cell 9
    verdict A1-2 "a second apply changes nothing of the account" \
        '[ "$A1_WORLD_AFTER_CREATION" = "$(agent_world)" ] && grep -qE "changed=0 " "$EVIDENCE/cell9.log"'
    return
}

refuses_foreign_shape() {  # refuses_foreign_shape <name> <make> <undo> [reason] [dry]: the play fails with exit 3 and nothing, not even cloudflared's files, moves
    local name=$1 make=$2 undo=$3 reason=${4:-nothing was written} before after code dry_code dry_after  # NOSONAR(shelldre:S1481) read inside the condition that verdict evals
    eval "$make"
    before=$(agent_world)
    at_terminal "a1-3-$name" "$HAL_BIN setup"
    code=$?
    after=$(agent_world)
    if [[ ${5:-} == dry ]]; then
        at_terminal "a1-3-$name-dry" "$HAL_BIN setup --dry-run"
        dry_code=$?
        dry_after=$(agent_world)
    fi
    eval "$undo"
    verdict A1-3 "$name: the apply refuses with exit 3 and nothing was written" \
        '[ $code -eq 3 ] && in_log "a1-3-$name" "$reason" && ! in_log "a1-3-$name" "$OPERATORS_SKIP" && [ "$before" = "$after" ]'
    if [[ ${5:-} == dry ]]; then
        verdict A1-3 "$name: the dry run refuses with exit 3 and nothing was written" \
            '[ $dry_code -eq 3 ] && in_log "a1-3-$name-dry" "$reason" && [ "$before" = "$dry_after" ]'
    fi
    verdict A1-3 "$name: undone, the account is dormant again" agent_is_dormant
    return
}

move_entry() {  # move_entry <file> <name> <first|last>: the entry of that name to the top or bottom of the file, in place
    local file=$1 name=$2 where=$3 rest
    rest=$(grep -v "^$name:" "$file")
    if [[ $where == first ]]; then { grep "^$name:" "$file"; echo "$rest"; } >"$file.new"; else { echo "$rest"; grep "^$name:" "$file"; } >"$file.new"; fi
    cat "$file.new" >"$file"
    rm "$file.new"
    return
}

set_passwd_field() {  # set_passwd_field <name> <field number> <value>
    local name=$1 field=$2 value=$3
    awk -F: -v OFS=: -v name="$name" -v field="$field" -v value="$value" '$1 == name { $field = value } 1' /etc/passwd >/etc/passwd.new
    cat /etc/passwd.new >/etc/passwd
    rm /etc/passwd.new
    return
}

drop_entry() {  # drop_entry <file> <name or id>: the entry keyed by it
    local file=$1 entry=$2
    sed -i "/^$entry:/d" "$file"
    return
}

remove_account() {  # the account, its group and its home, as a cell that needs the account absent starts
    userdel --remove agent
    groupdel agent 2>/dev/null
    return 0
}

recreate_account() {
    at_terminal a1-3-recreate "$HAL_BIN setup"
    return
}

lowest_free_id() {  # lowest_free_id [skip]: the lowest id from 1000 up that no user and no group has, other than the one named
    local id
    for ((id = 1000; id < 60000; id++)); do
        [[ $id == "${1:-}" ]] && continue
        getent passwd "$id" >/dev/null || getent group "$id" >/dev/null || { echo "$id"; return 0; }
    done
    return 1
}

free_system_id() {  # the highest id below 1000 that no user and no group has
    local id
    for ((id = 999; id > 100; id--)); do
        getent passwd "$id" >/dev/null || getent group "$id" >/dev/null || { echo "$id"; return 0; }
    done
    return 1
}

create_account_with_ids() {  # create_account_with_ids <uid> <gid>: the dormant account by hand, with those ids
    local uid=$1 gid=$2
    groupadd --gid "$gid" agent
    useradd --create-home --home-dir "$AGENT_HOME" --gid "$gid" --shell /usr/sbin/nologin --uid "$uid" -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0 agent
    return
}

cell_a1_3() {
    AGENT_ID=$(id -u agent)
    AGENT_GID=$(id -g agent)
    refuses_foreign_shape "an extra group" 'usermod --append --groups bystander agent' 'gpasswd --delete agent bystander'
    refuses_foreign_shape "a subuid entry" 'echo agent:100000:65536 >>/etc/subuid' 'drop_entry /etc/subuid agent'
    refuses_foreign_shape "the shell bash" 'usermod --shell /bin/bash agent' 'usermod --shell /usr/sbin/nologin agent'
    refuses_foreign_shape "linger" 'loginctl enable-linger agent' 'loginctl disable-linger agent'
    refuses_foreign_shape "a usable password" 'passwd --delete agent >/dev/null' 'usermod --lock agent'
    refuses_foreign_shape "a subgid entry" 'echo agent:100000:65536 >>/etc/subgid' 'drop_entry /etc/subgid agent'
    refuses_foreign_shape "a numeric subuid entry for its uid" 'echo "$AGENT_ID:100000:65536" >>/etc/subuid' 'drop_entry /etc/subuid $AGENT_ID' \
        "a subuid or subgid entry"
    refuses_foreign_shape "a numeric subgid entry for its uid" 'echo "$AGENT_ID:100000:65536" >>/etc/subgid' 'drop_entry /etc/subgid $AGENT_ID' \
        "a subuid or subgid entry"
    cell_a1_3_homes
    cell_a1_3_shared_ids
    cell_a1_3_account_absent
    cell_a1_3_cron_files
    return
}

cell_a1_3_homes() {  # an existing account whose home is not its own; the dry run refuses too
    refuses_foreign_shape "another home" 'usermod --home /srv/agent-elsewhere agent' "usermod --home $AGENT_HOME agent" "a home other than" dry
    refuses_foreign_shape "a home that is a link" "mv $AGENT_HOME $AGENT_HOME.real && ln -s $AGENT_HOME.real $AGENT_HOME" \
        "rm $AGENT_HOME && mv $AGENT_HOME.real $AGENT_HOME" "a home that is a link or not a directory" dry
    refuses_foreign_shape "a home that is a file of its own" "mv $AGENT_HOME $AGENT_HOME.real && touch $AGENT_HOME && chown agent:agent $AGENT_HOME" \
        "rm $AGENT_HOME && mv $AGENT_HOME.real $AGENT_HOME" "a home that is a link or not a directory" dry
    refuses_foreign_shape "a home owned by root, group agent" "chown root:agent $AGENT_HOME" "chown agent:agent $AGENT_HOME" "a home not owned by agent:agent" dry
    refuses_foreign_shape "a home of group root, owner agent" "chgrp root $AGENT_HOME" "chgrp agent $AGENT_HOME" "a home not owned by agent:agent" dry
    refuses_foreign_shape "a home that is missing" "mv $AGENT_HOME $AGENT_HOME.real" "mv $AGENT_HOME.real $AGENT_HOME" "a home that is missing" dry
    refuses_foreign_shape "a line in cron.allow" 'echo agent >/etc/cron.allow' 'rm -f /etc/cron.allow'
    return
}

cell_a1_3_shared_ids() {  # a uid or gid the account shares, with the shared name before and after the agent's; `hal setup` itself never guesses the role
    refuses_foreign_shape "the uid of bystander, agent listed after" 'set_passwd_field agent 3 $(id -u bystander)' 'set_passwd_field agent 3 $AGENT_ID' \
        "a uid shared with"
    refuses_foreign_shape "the uid of bystander, agent listed first" 'set_passwd_field agent 3 $(id -u bystander); move_entry /etc/passwd agent first' \
        'set_passwd_field agent 3 $AGENT_ID; move_entry /etc/passwd agent last' "a uid shared with"
    refuses_foreign_shape "the uid of the running user, agent listed after" 'set_passwd_field agent 3 $(id -u tester)' 'set_passwd_field agent 3 $AGENT_ID' \
        "must have a uid of its own"
    refuses_foreign_shape "the uid of the running user, agent listed first" 'set_passwd_field agent 3 $(id -u tester); move_entry /etc/passwd agent first' \
        'set_passwd_field agent 3 $AGENT_ID; move_entry /etc/passwd agent last' "must have a uid of its own"
    refuses_foreign_shape "its gid in another group, listed after" 'groupadd --non-unique --gid $AGENT_GID sharer' 'drop_entry /etc/group sharer; drop_entry /etc/gshadow sharer' "a gid shared with sharer"
    refuses_foreign_shape "its gid in another group, listed first" 'groupadd --non-unique --gid $AGENT_GID sharer; move_entry /etc/group sharer first' \
        'drop_entry /etc/group sharer; drop_entry /etc/gshadow sharer' "a gid shared with sharer"
    refuses_foreign_shape "an id below 1000 for uid and gid" 'remove_account; create_account_with_ids $(free_system_id) $(free_system_id)' \
        'remove_account; recreate_account' "an id that is not one uid and gid from 1000 up" dry
    refuses_foreign_shape "a uid and a gid that differ" 'remove_account; create_account_with_ids $(lowest_free_id) $(lowest_free_id $(lowest_free_id))' \
        'remove_account; recreate_account' "an id that is not one uid and gid from 1000 up" dry
    refuses_foreign_shape "a primary gid that is not the group agent's" 'set_passwd_field agent 4 $(id -g bystander)' 'set_passwd_field agent 4 $AGENT_GID' \
        "a primary group other than"
    refuses_foreign_shape "a primary gid no group has a name for, so its groups cannot be read" 'set_passwd_field agent 4 5000' 'set_passwd_field agent 4 $AGENT_GID' \
        "groups that could not be read" dry
    return
}

cell_a1_3_account_absent() {  # no account yet: what is in its way is refused before anything is written; ids and subid files of a new one
    refuses_foreign_shape "a home path already taken by a directory" "remove_account; mkdir $AGENT_HOME" "rmdir $AGENT_HOME; recreate_account" \
        "a home path that is already taken" dry
    refuses_foreign_shape "a home path already taken by a file" "remove_account; touch $AGENT_HOME" "rm $AGENT_HOME; recreate_account" \
        "a home path that is already taken" dry
    refuses_foreign_shape "a lone group agent" 'remove_account; groupadd agent' 'groupdel agent; recreate_account' "a group agent without the account (sudo groupdel agent removes it)"
    cell_a1_3_failed_useradd
    cell_a1_3_ids_of_the_new_account
    cell_a1_3_without_subid_files
    return
}

cell_a1_3_failed_useradd() {  # useradd cannot lock /etc/passwd: the apply fails, no group of that name is left, the next apply converges
    local code
    remove_account
    echo $$ >/etc/passwd.lock
    at_terminal a1-3-useradd-fails "$HAL_BIN setup"
    code=$?
    rm /etc/passwd.lock
    verdict A1-3 "useradd fails on a held lock: the apply fails and leaves no group agent" '[ $code -ne 0 ] && ! getent group agent >/dev/null'
    recreate_account
    verdict A1-3 "the lock gone, the next apply creates the account" 'agent_is_dormant'
    return
}

cell_a1_3_ids_of_the_new_account() {  # a numeric subuid or subgid entry for the lowest free id: the new account takes the next id, one for uid and gid
    local file skipped expected code
    for file in /etc/subuid /etc/subgid; do
        remove_account
        skipped=$(lowest_free_id)
        echo "$skipped:100000:65536" >>"$file"
        expected=$(lowest_free_id "$skipped")
        at_terminal a1-3-new-ids "$HAL_BIN setup"
        code=$?
        verdict A1-3 "a numeric entry in $file for the lowest free id: exit 0, the account gets the next id for uid and gid" \
            '[ $code -eq 0 ] && [[ $(id -u agent) == "$expected" && $(id -g agent) == "$expected" ]] && agent_is_dormant'
        drop_entry "$file" "$skipped"
    done
    remove_account
    recreate_account
    verdict A1-3 "the entries gone, the apply creates the account at the lowest free id again" '[[ $(id -u agent) == "$AGENT_ID" ]] && agent_is_dormant'
    return
}

cell_a1_3_without_subid_files() {  # the subordinate id files do not exist: an existing and a new account both converge, and no file appears
    local code
    mv /etc/subuid /etc/subuid.proof
    mv /etc/subgid /etc/subgid.proof
    at_terminal a1-3-no-subid-existing "$HAL_BIN setup"
    code=$?
    verdict A1-3 "no subuid and subgid file, the account exists: exit 0, changed=0, dormant" \
        '[ $code -eq 0 ] && in_log a1-3-no-subid-existing "changed=0 " && agent_is_dormant'
    remove_account
    at_terminal a1-3-no-subid-new "$HAL_BIN setup"
    code=$?
    verdict A1-3 "no subuid and subgid file, a new account: exit 0, dormant, and no file was created" \
        '[ $code -eq 0 ] && agent_is_dormant && [ ! -e /etc/subuid ] && [ ! -e /etc/subgid ]'
    mv /etc/subuid.proof /etc/subuid
    mv /etc/subgid.proof /etc/subgid
    return
}

keep_the_cron_deny_of() {  # keep_the_cron_deny_of <entry> <owner:group> <mode>: the file the operator already has
    local entry=$1 owner=$2 mode=$3
    printf '%s\n' "$entry" >/etc/cron.deny
    chown "$owner" /etc/cron.deny
    chmod "$mode" /etc/cron.deny
    return
}

cron_deny_is() {  # cron_deny_is <entries> <owner:group> <mode>
    local entries=$1 owner=$2 mode=$3
    [[ $(tr '\n' ' ' </etc/cron.deny) == "$entries " ]] && [[ $(stat -c '%U:%G' /etc/cron.deny) == "$owner" ]] && [[ $(stat -c %a /etc/cron.deny) == "$mode" ]]
    return
}

cell_a1_3_cron_files() {  # the states of the files; the proof image has no cron, so crontab itself is not driven
    local code
    keep_the_cron_deny_of bob root:bystander 640
    at_terminal a1-3-cron-deny "$HAL_BIN setup"
    code=$?
    verdict A1-3 "an existing cron.deny keeps owner and mode and gains the agent line" \
        '[ $code -eq 0 ] && cron_deny_is "bob agent" root:bystander 640'
    keep_the_cron_deny_of bob root:root 644
    echo alice >/etc/cron.allow
    at_terminal a1-3-cron-allow "$HAL_BIN setup"
    code=$?
    verdict A1-3 "a cron.allow without the agent denies it already: exit 0, cron.deny left alone" \
        '[ $code -eq 0 ] && cron_deny_is bob root:root 644 && [[ $(cat /etc/cron.allow) == alice ]]'
    rm -f /etc/cron.allow
    keep_the_cron_deny_of agent root:root 644
    return
}

install_wheel_for() {  # install_wheel_for <user>: the packaged `hal`, in that user's own home
    local user=$1
    run_as "$user" "install-$user" uv tool install /proof/*.whl
    return
}

cell_a1_4_and_5() {
    local dry apply refused
    install_wheel_for agent
    run_as agent a1-4-dry "$AGENT_HOME/.local/bin/hal" setup --dry-run
    dry=$?
    verdict A1-4 "as agent the dry run exits 0, shows the per-user steps and skips the operator's" \
        '[ $dry -eq 0 ] && row_in_log a1-4-dry "commit hook" "will change" &&
         row_in_log a1-4-dry timers skipped && row_in_log a1-4-dry system skipped && row_in_log a1-4-dry secrets skipped'
    run_as agent a1-5-no-terminal "$AGENT_HOME/.local/bin/hal" setup
    refused=$?
    verdict A1-5b "as agent without a terminal and with the hook open setup prints the plan and refuses with exit 4; hook files and config stay" \
        '[ $refused -eq 4 ] && plan_row_in_log a1-5-no-terminal "commit hook" "will change" && in_log a1-5-no-terminal "setup asks yes at a terminal · nothing changed" &&
         [ ! -e "$AGENT_HOME/.local/share/home/git-hooks" ] && [ -z "$(runuser -u agent -- env -i HOME="$AGENT_HOME" git config --global --get core.hooksPath)" ]'
    PROOF_USER=agent at_terminal a1-5-apply "$AGENT_HOME/.local/bin/hal setup"
    apply=$?
    verdict A1-5 "as agent at a terminal setup asks one yes and exits 0 with the same skips, no sudo prompt, no user unit linked" \
        '[ $apply -eq 0 ] && yes_asked_once a1-5-apply && row_in_log a1-5-apply "commit hook" changed && row_in_log a1-5-apply system skipped &&
         ! grep -qi "password" "$EVIDENCE/a1-5-apply.log" && [ ! -e "$AGENT_HOME/.config/systemd/user" ]'
    verdict A1-5 "the account is still dormant after the agent's own apply" agent_is_dormant
    run_as agent y7 "$AGENT_HOME/.local/bin/hal" setup
    apply=$?
    verdict Y7 "the agent with the hook in place and nothing open gets no question and no terminal is needed: up to date, exit 0" \
        '[ $apply -eq 0 ] && ! grep -q "Type .*yes" "$EVIDENCE/y7.log" && in_log y7 "✓ setup up to date"'
    return
}

cell_a1_6() {
    verdict A1-6 "the operator's dry run and apply print no skip and still run the user units and the system step" \
        '! grep -q "$OPERATORS_SKIP" "$EVIDENCE"/cell1.log "$EVIDENCE"/cell9.log "$EVIDENCE"/cell10.log &&
         row_in_log cell9 timers "[a-z]+" && row_in_log cell9 system unchanged && row_in_log cell10 system "will change"'
    return
}

cell_a1_7() {
    local dry apply
    loginctl enable-linger bystander
    timeout 60 bash -c 'until systemctl is-active --quiet "user@$(id -u bystander).service"; do sleep 1; done'
    install -d -o bystander -g bystander /home/bystander/srv/hal
    cp -r /proof/tunnel /home/bystander/srv/hal/
    chown -R bystander:bystander /home/bystander/srv
    install_wheel_for bystander
    run_as bystander a1-7-dry /home/bystander/.local/bin/hal setup --dry-run
    dry=$?
    verdict A1-7 "a bystander's dry run behaves as today: not checked, exit 0, nothing skipped" \
        '[ $dry -eq 0 ] && row_in_log a1-7-dry system "not checked" && in_log a1-7-dry "needs sudo at a terminal" && ! grep -q "$OPERATORS_SKIP" "$EVIDENCE/a1-7-dry.log"'
    run_as bystander a1-7-apply /home/bystander/.local/bin/hal setup
    apply=$?
    verdict A1-7 "a bystander's setup without a terminal is refused after its plan, exit 4, nothing skipped" \
        '[ $apply -eq 4 ] && plan_row_in_log a1-7-apply system "not checked" && in_log a1-7-apply "setup asks yes at a terminal · nothing changed" && ! grep -q "$OPERATORS_SKIP" "$EVIDENCE/a1-7-apply.log"'
    return
}

cell_a1_8() {
    verdict A1-8 "agent may not read ~tester or its secrets, use sudo or the Docker socket, and has no login shell" agent_is_refused
    return
}

cell_a1_9() {  # after a reboot
    verdict A1-9 "after a reboot the account is still dormant" agent_is_dormant
    verdict A1-9 "after a reboot agent is still refused" agent_is_refused
    return
}

# The mail cells (D3-D8): `hal check` as the operator, with no graphical session, against a sink that speaks SMTP with a
# test CA the system trust store knows (or does not). The sink and the CA are made here; the password is a canary that must
# reach the sink only as the AUTH of a verified TLS session.
MAIL_HOST=mail.proof.test
MAIL_DIR=/proof/mail
MAIL_CANARY=$(openssl rand -hex 24)
export MAIL_CANARY
MAIL_STATE=/home/tester/.local/state/hal
SINK_PID_FILE=$EVIDENCE/mail-sink.pid

make_mail_ca() {  # make_mail_ca <name>: a CA and a certificate for $MAIL_HOST signed by it, in $MAIL_DIR
    local name=$1
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=proof $name CA" \
        -keyout "$MAIL_DIR/$name-ca.key" -out "$MAIL_DIR/$name-ca.crt" 2>/dev/null &&
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$MAIL_HOST" \
            -keyout "$MAIL_DIR/$name.key" -out "$MAIL_DIR/$name.csr" 2>/dev/null &&
        openssl x509 -req -days 2 -in "$MAIL_DIR/$name.csr" -CA "$MAIL_DIR/$name-ca.crt" -CAkey "$MAIL_DIR/$name-ca.key" \
            -CAcreateserial -extfile <(printf 'subjectAltName=DNS:%s\n' "$MAIL_HOST") -out "$MAIL_DIR/$name.crt" 2>/dev/null
    return
}

write_mail_sink() {
    cat >/proof/mail_sink.py <<'PYTHON'
import asyncio
import os
import email
import email.policy
import ssl
import sys

from aiosmtpd.smtp import SMTP, AuthResult, LoginPassword

mode, port, log_path, certificate_name = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]


def note(text):
    with open(log_path, "a") as log:
        log.write(text + "\n")


class Handler:
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        note(f"MAIL FROM {address}")
        envelope.mail_from = address
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        note(f"RCPT TO {address}")
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        note("SUBJECT " + str(email.message_from_bytes(envelope.content, policy=email.policy.default)["Subject"]))
        return "250 OK"


class LoggingSmtp(SMTP):
    def connection_made(self, transport):
        note(f"CONNECT ssl={transport.get_extra_info('ssl_object') is not None}")
        super().connection_made(transport)

    async def smtp_STARTTLS(self, arg):
        note("STARTTLS")
        return await super().smtp_STARTTLS(arg)

    async def smtp_AUTH(self, arg):
        note("AUTH")
        return await super().smtp_AUTH(arg)


def authenticate(server, session, envelope, mechanism, data):
    assert isinstance(data, LoginPassword)
    note(f"CREDENTIALS user_matches={data.login == b'home@proof.test'} password_matches={data.password.decode() == os.environ['MAIL_CANARY']}")
    return AuthResult(success=mode != "reject", handled=False)


async def hold(reader, writer):  # accepts and never says a word
    note("CONNECT stall")
    await asyncio.sleep(3600)


async def main():
    loop = asyncio.get_running_loop()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"/proof/mail/{certificate_name}.crt", f"/proof/mail/{certificate_name}.key")
    if mode == "stall":
        server = await asyncio.start_server(hold, "127.0.0.1", port)
    elif mode == "plain":
        server = await loop.create_server(lambda: LoggingSmtp(Handler(), hostname="sink"), "127.0.0.1", port)
    elif mode == "implicit":
        server = await loop.create_server(lambda: LoggingSmtp(Handler(), hostname="sink", authenticator=authenticate, auth_required=True, auth_require_tls=False), "127.0.0.1", port, ssl=context)
    else:
        server = await loop.create_server(
            lambda: LoggingSmtp(Handler(), hostname="sink", tls_context=context, require_starttls=True, authenticator=authenticate, auth_required=True),
            "127.0.0.1",
            port,
        )
    note("READY")
    await server.serve_forever()


asyncio.run(main())
PYTHON
    return
}

start_mail_sink() {  # start_mail_sink <log name> <mode: starttls|plain|implicit|reject|stall> <port> <certificate: trusted|untrusted>
    local name=$1 mode=$2 port=$3 certificate=$4
    : >"$EVIDENCE/$name.log"
    timeout 300 python3 /proof/mail_sink.py "$mode" "$port" "$EVIDENCE/$name.log" "$certificate" 2>>"$EVIDENCE/$name.err" &
    echo $! >"$SINK_PID_FILE"
    timeout 20 bash -c "until grep -qx READY '$EVIDENCE/$name.log'; do sleep 0.2; done"
    return
}

stop_mail_sink() {
    kill "$(cat "$SINK_PID_FILE")" 2>/dev/null
    wait 2>/dev/null
    return 0
}

sink_events() {  # sink_events <log name>: what the sink saw, after it was ready
    local name=$1
    awk 'seen {print} /^READY$/ {seen=1}' "$EVIDENCE/$name.log"
    return
}

set_up_mail_account() {  # set_up_mail_account <port>: the operator's two files, the account on that port and the canary as password
    install -d -o tester -g tester -m 0700 /home/tester/.secrets/smtp
    printf 'host = "%s"\nport = %s\nuser = "home@proof.test"\nto = "me@proof.test"\n' "$MAIL_HOST" "$1" >/home/tester/.secrets/smtp/account.toml
    printf '%s' "$MAIL_CANARY" >/home/tester/.secrets/smtp/password
    chown tester:tester /home/tester/.secrets/smtp/account.toml /home/tester/.secrets/smtp/password
    chmod 600 /home/tester/.secrets/smtp/account.toml /home/tester/.secrets/smtp/password
    return
}

mail_run() {  # mail_run <log>: one `hal check` with news that has never been delivered, as the operator without a session
    local log=$1
    rm -f "$MAIL_STATE/check-findings.txt"
    run_as tester "$log" "$HAL_BIN" check
    return 0
}

mail_run_has_set() {
    [[ -s $MAIL_STATE/check-findings.txt ]]
    return
}

cells_mail() {
    local started advanced
    mkdir -p "$MAIL_DIR"
    make_mail_ca trusted && make_mail_ca untrusted && write_mail_sink
    cp "$MAIL_DIR/trusted-ca.crt" /usr/local/share/ca-certificates/proof-trusted-ca.crt && update-ca-certificates >"$EVIDENCE/ca.log" 2>&1
    grep -qx "127.0.0.1 $MAIL_HOST" /etc/hosts || echo "127.0.0.1 $MAIL_HOST" >>/etc/hosts
    # What msmtp would read without --host: a config that switches the certificate check off, at both places it looks.
    printf 'defaults\ntls_certcheck off\n' | tee /etc/msmtprc /home/tester/.msmtprc >/dev/null
    chown tester:tester /home/tester/.msmtprc
    chmod 600 /home/tester/.msmtprc
    # The shim records msmtp's argv, which must never hold the password, and runs the real msmtp.
    cat >/usr/local/bin/msmtp <<'SHIM'
#!/bin/sh
printf '%s\n' "$@" >>/proof/evidence/msmtp-argv.log
exec /usr/bin/msmtp "$@"
SHIM
    chmod 755 /usr/local/bin/msmtp
    install -o tester -g tester -m 0600 /dev/null "$EVIDENCE/msmtp-argv.log"

    set_up_mail_account 587
    start_mail_sink sink-d3 starttls 587 trusted
    mail_run cell-d3
    mail_run_has_set
    advanced=$?
    run_as tester cell-d3-rerun "$HAL_BIN" check
    stop_mail_sink
    verdict D3 "the sink saw STARTTLS, then AUTH with the account and the canary, then MAIL FROM, RCPT TO and the subject" \
        '[ "$(sink_events sink-d3 | grep -x -e STARTTLS -e AUTH | tr "\n" " ")" = "STARTTLS AUTH " ] &&
         sink_events sink-d3 | grep -qx "CREDENTIALS user_matches=True password_matches=True" &&
         sink_events sink-d3 | grep -qx "MAIL FROM home@proof.test" && sink_events sink-d3 | grep -qx "RCPT TO me@proof.test" &&
         sink_events sink-d3 | grep -q "^SUBJECT PC check: "'
    verdict D3 "the argv log and the run's output never hold the canary, and the argv asks for STARTTLS" \
        '! grep -qF -- "$MAIL_CANARY" "$EVIDENCE/msmtp-argv.log" "$EVIDENCE/cell-d3.log" && grep -qx -e "--tls-starttls=on" "$EVIDENCE/msmtp-argv.log"'
    verdict D3 "with no graphical session the delivered mail advanced the set, and the rerun sent nothing" \
        '[ $advanced -eq 0 ] && [ "$(sink_events sink-d3 | grep -c "^SUBJECT ")" -eq 1 ]'

    set_up_mail_account 25
    start_mail_sink sink-d4 plain 25 trusted
    mail_run cell-d4
    stop_mail_sink
    verdict D4 "a sink without STARTTLS gets no mail, no AUTH, and the news is kept" \
        'sink_events sink-d4 | grep -qx "CONNECT ssl=False" &&
         [ -z "$(sink_events sink-d4 | grep -e "^AUTH" -e "^CREDENTIALS" -e "^SUBJECT")" ] && in_log cell-d4 "mail failed: msmtp could not deliver via $MAIL_HOST:25" && ! mail_run_has_set'

    set_up_mail_account 587
    start_mail_sink sink-d5 starttls 587 untrusted
    mail_run cell-d5
    stop_mail_sink
    verdict D5 "a certificate the system does not trust is refused despite msmtprc files that switch the check off: no AUTH, news kept" \
        'sink_events sink-d5 | grep -qx "CONNECT ssl=False" && sink_events sink-d5 | grep -qx STARTTLS &&
         [ -z "$(sink_events sink-d5 | grep -e "^AUTH" -e "^CREDENTIALS" -e "^SUBJECT")" ] && in_log cell-d5 "mail failed: msmtp could not deliver via" && ! mail_run_has_set'

    set_up_mail_account 465
    start_mail_sink sink-d6 implicit 465 trusted
    mail_run cell-d6
    stop_mail_sink
    verdict D6 "implicit TLS on 465: the sink's first event is a TLS connection, and the mail arrived" \
        '[ "$(sink_events sink-d6 | head -n 1)" = "CONNECT ssl=True" ] && ! sink_events sink-d6 | grep -q "ssl=False" && sink_events sink-d6 | grep -q "^SUBJECT "'

    set_up_mail_account 587
    start_mail_sink sink-d7 reject 587 trusted
    mail_run cell-d7
    stop_mail_sink
    verdict D7 "a rejected AUTH is one failure line and keeps the news" 'sink_events sink-d7 | grep -qx AUTH && sink_events sink-d7 | grep -qx "CREDENTIALS user_matches=True password_matches=True" && ! sink_events sink-d7 | grep -q "^SUBJECT " && in_log cell-d7 "mail failed: msmtp could not deliver via $MAIL_HOST:587" && ! mail_run_has_set'
    start_mail_sink sink-d7-good starttls 587 trusted
    mail_run cell-d7-again
    stop_mail_sink
    verdict D7 "the next run against a good sink mails the news" 'sink_events sink-d7-good | grep -q "^SUBJECT " && mail_run_has_set'

    start_mail_sink sink-d8 stall 587 trusted
    started=$SECONDS
    mail_run cell-d8
    stop_mail_sink
    verdict D8 "a sink that never greets ends the run within 45 s and keeps the news" 'sink_events sink-d8 | grep -qx "CONNECT stall" && [ $((SECONDS - started)) -le 45 ] && in_log cell-d8 "mail failed: msmtp could not deliver via" && ! mail_run_has_set'
    rm -f /etc/msmtprc /home/tester/.msmtprc /usr/local/bin/msmtp
    plant_fake_secrets >/dev/null
    return
}

cells_agent() {
    put_operator_in_docker_group
    cell_a1_4_and_5
    cell_a1_6
    cell_a1_7
    cell_a1_8
    return
}

# rsyslog's six files and their rotations (#422, cells R0-R7). The names are the playbook's `rsyslog_file_names`, written
# here once because the proof must not read what it checks; the bookkeeping logs are the ones that must stay.
RSYSLOG_NAMES=(syslog auth.log kern.log mail.log mail.err ufw.log)
RSYSLOG_SUFFIXES=("" .1 .2.gz .3.gz)
BOOKKEEPING_LOGS=(/var/log/dpkg.log /var/log/cloud-init.log /var/log/alternatives.log)
PLANTED_FILES="$EVIDENCE/rsyslog-planted.txt"
PACKAGE_CONFFILES="$EVIDENCE/rsyslog-conffiles.txt"
JOURNALD_CONFIG_BEFORE="$EVIDENCE/journald-config-before.txt"

plant_rsyslog_files() {  # a file for every name and rotation, and a bookkeeping log of the installer
    local name suffix file
    : >"$PLANTED_FILES"
    for name in "${RSYSLOG_NAMES[@]}"; do
        for suffix in "${RSYSLOG_SUFFIXES[@]}"; do
            file="/var/log/$name$suffix"
            echo "planted by the proof" >>"$file"
            echo "$file" >>"$PLANTED_FILES"
        done
    done
    for file in "${BOOKKEEPING_LOGS[@]}"; do
        echo "planted by the proof" >>"$file"
    done
    return
}

record_rsyslog_before() {  # what the package owns and what journald is set to, read before the first apply changes either
    dpkg-query -W -f='${Conffiles}\n' rsyslog | awk 'NF { print $1 }' >"$PACKAGE_CONFFILES"
    systemd-analyze cat-config systemd/journald.conf >"$JOURNALD_CONFIG_BEFORE"
    return
}

all_planted_files_exist() {
    local file
    while read -r file; do
        [[ -e $file ]] || return 1
    done <"$PLANTED_FILES"
    return
}

no_planted_file_exists() {
    local file
    while read -r file; do
        [[ ! -e $file ]] || return 1
    done <"$PLANTED_FILES"
    return
}

cell_r0() {  # after the refused runs of cells 12 and 13 and the dry run of cell 10: nothing was deleted
    verdict R0 "the dry run says it would change, names rsyslog and a planted file" \
        'row_in_log cell10 system "will change" && in_log cell10 "rsyslog" && in_log cell10 "/var/log/mail.err.1"'
    verdict R0 "the refused runs and the dry run left the package and every planted file in place" \
        'dpkg -s rsyslog >/dev/null 2>&1 && all_planted_files_exist'
    return
}

journal_has_line_of() {  # journal_has_line_of <tag>: within 30 s
    local tag=$1 waited=0
    until journalctl --no-pager --quiet --identifier "$tag" 2>/dev/null | grep -q .; do
        (( waited++ >= 30 )) && return 1
        sleep 1
    done
    return 0
}

cell_r1() {
    local conffile missing=()
    while read -r conffile; do
        [[ ! -e $conffile ]] || missing+=("$conffile")
    done <"$PACKAGE_CONFFILES"
    verdict R1 "rsyslog is purged: no package, no unit, no conffile of it left (${missing[*]:-none})" \
        '[ -s "$PACKAGE_CONFFILES" ] && ! dpkg -s rsyslog >/dev/null 2>&1 && ! systemctl cat rsyslog.service >/dev/null 2>&1 && ! systemctl cat syslog.service >/dev/null 2>&1 && [[ ${#missing[@]} -eq 0 ]]'
    verdict R1 "syslog.socket is inactive" '[[ $(systemctl is-active syslog.socket) == inactive ]]'
    verdict R1 "the six files and every archive are gone, and none was copied to the backups" \
        'no_planted_file_exists && [[ -z $(find /var/backups/home-setup -name "*.log*" -o -name "syslog*" -o -name "mail.err*" 2>/dev/null) ]]'
    return
}

cell_r2() {
    local since
    since=$(date '+%Y-%m-%d %H:%M:%S')
    seq 1000 | logger --tag r2-probe
    sleep 2
    journalctl --no-pager --unit systemd-journald --since "$since" >"$EVIDENCE/r2-journald.txt" 2>&1
    verdict R2 "1000 lines without a syslog listener leave no \"Forwarding to syslog missed\"" \
        '! grep -q "Forwarding to syslog missed" "$EVIDENCE/r2-journald.txt"'
    verdict R2 "journald's configuration is what it was before the apply" \
        'systemd-analyze cat-config systemd/journald.conf | diff - "$JOURNALD_CONFIG_BEFORE"'
    return
}

cell_r2_after_boot() {
    verdict R2 "after the boot there is no syslog socket and journald's configuration is still what it was before the apply" \
        '[ ! -S /run/systemd/journal/syslog ] && systemd-analyze cat-config systemd/journald.conf | diff - "$JOURNALD_CONFIG_BEFORE"'
    return
}

cell_r3() {
    local log=$EVIDENCE/r3-sendmail.log
    echo "proof" | /usr/sbin/sendmail root >"$log" 2>&1
    verdict R3 "an unconfigured postfix sendmail still logs, and the line is in the journal" 'journal_has_line_of postfix/sendmail'
    return
}

cell_r6() {
    local file
    for file in "${BOOKKEEPING_LOGS[@]}"; do
        verdict R6 "$file stays" '[ -e "$file" ]'
    done
    return
}

cell_r7() {  # kerneloops reads /var/log/kern.log; what it does without it is the installed package's answer, recorded for the operator
    systemctl restart kerneloops >"$EVIDENCE/r7-restart.log" 2>&1
    sleep 2
    systemctl status kerneloops --no-pager >"$EVIDENCE/r7-status.log" 2>&1
    journalctl --no-pager --unit kerneloops --since '-1 min' >>"$EVIDENCE/r7-status.log" 2>&1
    verdict R7 "kerneloops restarts and is active without kern.log, or its failure is in r7-status.log for the head: $(systemctl is-active kerneloops)" \
        '[[ $(systemctl is-active kerneloops) == active ]]'
    return
}

cells_rsyslog_purged() {  # after the first apply, while the package is purged
    cell_r1
    cell_r2
    cell_r3
    cell_r6
    cell_r7
    return
}

cell_r4() {  # a run interrupted after the purge: the files are there again, one apply finishes it, the next changes nothing
    local first second
    plant_rsyslog_files
    at_terminal r4-first "$HAL_BIN setup"
    first=$?
    at_terminal r4-second "$HAL_BIN setup"
    second=$?
    verdict R4 "an apply after the purge deletes the files that came back" \
        '[ $first -eq 0 ] && row_in_log r4-first system changed && no_planted_file_exists'
    verdict R4 "the next apply changes nothing" '[ $second -eq 0 ] && grep -qE "changed=0 " "$EVIDENCE/r4-second.log" && row_in_log r4-second system unchanged'
    return
}

wait_for_engine() {  # the engine answers within 60 s; a socket that is stopped starts here
    local waited=0
    systemctl start docker.socket
    until docker info >"$EVIDENCE/engine-wait.txt" 2>&1; do
        (( waited++ >= 60 )) && { systemctl status docker --no-pager >"$EVIDENCE/engine-wait-status.txt" 2>&1; return 1; }
        sleep 1
    done
    return 0
}

docker_default_driver() {
    docker info --format '{{.LoggingDriver}}'
    return
}

docker_started_at() {
    systemctl show docker -p ExecMainStartTimestamp --value
    return
}

daemon_json_is() {  # daemon_json_is <JSON text>: the file means the same as the text
    local expected_text=$1
    python3 -c 'import json, sys; sys.exit(json.load(open(sys.argv[1])) != json.loads(sys.argv[2]))' "$DAEMON_JSON" "$expected_text"
    return
}

cell_dk1() {  # first in `fresh`, before any apply: the engine runs, answers, records its drivers, runs an imported rootfs offline and starts from no daemon.json
    local info="$EVIDENCE/dk1-info.txt" code
    wait_for_engine
    docker info >"$EVIDENCE/dk1-docker-info.txt" 2>&1
    docker info --format 'storage driver {{.Driver}}, default log driver {{.LoggingDriver}}' >"$info" 2>&1
    verdict DK1 "docker info answers with the default json-file log driver ($(cat "$info"))" 'grep -q "default log driver json-file" "$info"'
    docker import /usr/local/share/proof-rootfs.tar proof-rootfs >"$EVIDENCE/dk1-import.log" 2>&1
    docker run --rm --network none proof-rootfs /bin/busybox true >"$EVIDENCE/dk1-run.log" 2>&1
    code=$?
    verdict DK1 "a container of the imported rootfs runs with no network and exits 0" '[ $code -eq 0 ]'
    verdict DK1 "there is no /etc/docker/daemon.json" '[ ! -e "$DAEMON_JSON" ]'
    return
}

# The PC's daemon.json as nvidia-ctk wrote it: 128 bytes, four-space layout, no final newline.
write_the_pcs_daemon_json() {  # write_the_pcs_daemon_json <path>
    local target=$1
    printf '{\n    "runtimes": {\n        "nvidia": {\n            "args": [],\n            "path": "nvidia-container-runtime"\n        }\n    }\n}' >"$target"
    return
}

backups_of_daemon_json() {
    find "$BACKUP_DIR" -path '*/etc/docker/daemon.json' 2>/dev/null | sort
    return
}

engine_on_json_file_with() {  # engine_on_json_file_with <file: a path, or "" for none>: Docker restarted on json-file, daemon.json as given, no drop-in
    local source_file=$1
    rm -rf "$DOCKER_DROP_IN_DIR"
    systemctl daemon-reload
    rm -f "$DAEMON_JSON"
    [[ -z $source_file ]] || cp "$source_file" "$DAEMON_JSON"
    # Several restarts within a minute would hit the unit's start limit, which the proof's own setup must not trigger.
    systemctl reset-failed docker
    systemctl restart docker
    wait_for_engine
    [[ $(docker_default_driver) == json-file ]]
    return
}

cell_dk3_case() {  # cell_dk3_case <name> <daemon.json text> <text the refusal names> [dry]: exit 3, nothing moves, Docker is not touched
    local name=$1 content=$2 names=$3 flag= code before started file_before log="dk3-$1"
    [[ ${4:-} == dry ]] && flag=--dry-run
    printf '%s' "$content" >"$DAEMON_JSON"
    before=$(snapshot)
    started=$(docker_started_at)
    file_before=$(sha256sum <"$DAEMON_JSON")
    at_terminal "$log" "$HAL_BIN setup $flag"
    code=$?
    verdict DK3 "$name: refused with exit 3, naming $names" '[ $code -eq 3 ] && in_log "$log" "$names"'
    verdict DK3 "$name: daemon.json, edge's files and Docker's start time are unchanged" \
        '[ "$file_before" = "$(sha256sum <"$DAEMON_JSON")" ] && [ "$before" = "$(snapshot)" ] && [ "$started" = "$(docker_started_at)" ]'
    rm -f "$DAEMON_JSON"
    return
}

cell_dk3_before_the_first_apply() {  # the play would still write everything, and refuses a malformed file first
    cell_dk3_case "malformed file before the first apply" '{"runtimes": ' "$DAEMON_JSON is not valid JSON"
    return
}

cell_dk3() {  # after cell 1, so Docker and edge's files are in place and a write would be seen
    local code started
    cell_dk3_case "log-opts" '{"log-opts": {"max-size": "10m"}}' '`log-opts`' dry
    cell_dk3_case "log-driver json-file" '{"log-driver": "json-file"}' "other than $WANTED_DRIVER"
    cell_dk3_case "a top level that is not an object" '[]' "is not a JSON object"
    rm -f "$DAEMON_JSON"
    snapshot >"$EVIDENCE/dk3-before.txt"
    started=$(docker_started_at)
    systemctl stop docker.socket docker.service
    at_terminal dk3-down "$HAL_BIN setup"
    code=$?
    systemctl start docker.socket
    wait_for_engine
    verdict DK3 "Docker does not answer: refused with exit 3, naming Docker, nothing written" \
        '[ $code -eq 3 ] && in_log dk3-down "Docker does not answer" && [ ! -e "$DAEMON_JSON" ] && [ "$(snapshot)" = "$(cat "$EVIDENCE/dk3-before.txt")" ]'
    return
}

cell_dk2_merge() {  # the PC's file keeps runtimes and gains the one line; the old bytes are in the backup
    local code pc="$EVIDENCE/dk2-pc-daemon.json" backup changed_lines
    write_the_pcs_daemon_json "$pc"
    verdict DK2 "the PC-shaped fixture is exactly 128 bytes" '[ "$(stat -c %s "$pc")" -eq 128 ]'
    engine_on_json_file_with "$pc"
    at_terminal dk2-merge "$HAL_BIN setup"
    code=$?
    backup=$(backups_of_daemon_json | tail -1)
    changed_lines=$(diff --unified=0 "$pc" "$DAEMON_JSON" | grep -c '^[+-][^+-]')
    verdict DK2 "the PC's file is merged: runtimes equal as JSON, log-driver added, apply exits 0" \
        '[ $code -eq 0 ] && daemon_json_is "{\"log-driver\": \"$WANTED_DRIVER\", \"runtimes\": {\"nvidia\": {\"args\": [], \"path\": \"nvidia-container-runtime\"}}}"'
    verdict DK2 "the diff of the file is the one log-driver line" '[ "$changed_lines" -eq 1 ] && grep -qF "\"log-driver\": \"$WANTED_DRIVER\"," <(diff "$pc" "$DAEMON_JSON")'
    verdict DK2 "the old bytes are in the backup under /var/backups/home-setup" '[ -n "$backup" ] && cmp "$pc" "$backup"'
    return
}

cell_dk4_and_dk5() {  # a merged file with Docker still on json-file: one restart into the journal; running and stopped containers
    local code started backups_before checksum_before
    engine_on_json_file_with ""
    printf '{\n    "log-driver": "%s"\n}' "$WANTED_DRIVER" >"$DAEMON_JSON"
    docker run --detach --restart unless-stopped --network none --name dk5-running proof-rootfs /bin/busybox sleep 100000 >"$EVIDENCE/dk5-run.log" 2>&1
    docker run --detach --restart unless-stopped --network none --name dk5-stopped proof-rootfs /bin/busybox sleep 100000 >>"$EVIDENCE/dk5-run.log" 2>&1
    docker stop dk5-stopped >>"$EVIDENCE/dk5-run.log" 2>&1
    backups_before=$(backups_of_daemon_json)
    checksum_before=$(sha256sum <"$DAEMON_JSON")
    started=$(docker_started_at)
    at_terminal dk4-restart "$HAL_BIN setup"
    code=$?
    wait_for_engine
    verdict DK4 "merged file, Docker on json-file: the apply restarts Docker into the journal" \
        '[ $code -eq 0 ] && [ "$(docker_default_driver)" = "$WANTED_DRIVER" ] && [ "$started" != "$(docker_started_at)" ]'
    verdict DK4 "that apply leaves the file and the backups alone" \
        '[ "$checksum_before" = "$(sha256sum <"$DAEMON_JSON")" ] && [ "$backups_before" = "$(backups_of_daemon_json)" ]'
    verdict DK5 "after the restart the unless-stopped container runs and the one stopped by hand stays exited" \
        '[ "$(docker inspect --format "{{.State.Status}}" dk5-running)" = running ] && [ "$(docker inspect --format "{{.State.Status}}" dk5-stopped)" = exited ]'
    verdict DK5 "both keep json-file" \
        '[ "$(docker inspect --format "{{.HostConfig.LogConfig.Type}}" dk5-running dk5-stopped | sort -u)" = json-file ]'
    docker rm --force dk5-running dk5-stopped >/dev/null 2>&1
    return
}

cell_dk6() {  # a container created after the restart logs to the journal, and every reader still finds its line
    local line="dk6-line-$$" compose="$EVIDENCE/dk6-compose.yaml" project=dk6
    docker run --name dk6-plain --network none proof-rootfs /bin/busybox echo "$line" >"$EVIDENCE/dk6-run.log" 2>&1
    printf '%s\n' 'services:' '  probe:' '    image: proof-rootfs' '    pull_policy: never' '    network_mode: none' \
        "    command: [\"/bin/busybox\", \"echo\", \"$line-compose\"]" >"$compose"
    docker compose --file "$compose" --project-name "$project" up >"$EVIDENCE/dk6-compose-up.log" 2>&1
    verdict DK6 "a container created after the restart records the journal as its driver" \
        '[ "$(docker inspect --format "{{.HostConfig.LogConfig.Type}}" dk6-plain)" = "$WANTED_DRIVER" ]'
    verdict DK6 "its line is in docker logs" '[ "$(docker logs dk6-plain 2>&1)" = "$line" ]'
    verdict DK6 "its line is in docker compose logs --since" \
        'docker compose --file "$compose" --project-name "$project" logs --since 10m 2>&1 | grep -qF "$line-compose"'
    verdict DK6 "its line is in the journal under CONTAINER_NAME" \
        'journalctl --no-pager --output cat CONTAINER_NAME=dk6-plain 2>&1 | grep -qxF "$line"'
    docker compose --file "$compose" --project-name "$project" down >/dev/null 2>&1
    docker rm --force dk6-plain >/dev/null 2>&1
    return
}

install_the_conflicting_flag() {  # dockerd refuses a directive given as a flag and in the file, and --validate cannot see the flag
    local execstart
    execstart=$(systemctl cat docker.service | grep '^ExecStart=' | tail -1)
    mkdir -p "$DOCKER_DROP_IN_DIR"
    printf '%s\n' '[Service]' 'ExecStart=' "$execstart --log-driver json-file" >"$DOCKER_DROP_IN_DIR/proof-log-driver.conf"
    systemctl daemon-reload
    return
}

DOCKER_SHIM=/usr/local/bin/docker

install_a_docker_that_reports_json_file() {  # Docker restarts and starts, yet `docker info` names another default driver
    local real
    real=$(command -v docker)
    printf '%s\n' '#!/bin/sh' \
        "case \"\$*\" in *LoggingDriver*) echo json-file; exit 0 ;; esac" \
        "exec $real \"\$@\"" >"$DOCKER_SHIM"
    chmod 755 "$DOCKER_SHIM"
    return
}

cell_dk7_case() {  # cell_dk7_case <name> <state of the file before the apply: created|merged|earlier> <what daemon.json must be after, as JSON> <how Docker fails: flag|wrong-driver>
    local name=$1 state=$2 expected=$3 failure=${4:-flag} code backups_before pc="$EVIDENCE/dk7-pc-daemon.json"
    write_the_pcs_daemon_json "$pc"
    case $state in
        created) engine_on_json_file_with "" ;;
        merged) engine_on_json_file_with "$pc" ;;
        earlier) engine_on_json_file_with ""; printf '{"log-driver": "%s"}' "$WANTED_DRIVER" >"$DAEMON_JSON" ;;
        *) echo "cell_dk7_case: unknown state $state" >&2; return 1 ;;
    esac
    if [[ $failure = flag ]]; then install_the_conflicting_flag; else install_a_docker_that_reports_json_file; fi
    backups_before=$(backups_of_daemon_json)
    at_terminal "dk7-$state-$failure" "$HAL_BIN setup"
    code=$?
    verdict DK7 "$name: the apply exits 3 naming the rescue" '[ $code -eq 3 ] && in_log "dk7-$state-$failure" "was written back without"'
    if [[ $failure = wrong-driver ]]; then
        verdict DK7 "$name: the apply saw Docker start and name json-file, not the journal" 'in_log "dk7-$state-$failure" "Docker reports json-file"'
    fi
    verdict DK7 "$name: daemon.json is JSON-equal to the state before this slice" "daemon_json_is '$expected'"
    verdict DK7 "$name: no backup was deleted" '[ -z "$(comm -23 <(echo "$backups_before") <(backups_of_daemon_json))" ]'
    verdict DK7 "$name: Docker is active and answering" 'systemctl is-active --quiet docker && docker info >/dev/null 2>&1'
    rm -rf "$DOCKER_DROP_IN_DIR"
    rm -f "$DOCKER_SHIM"
    verdict DK7 "$name: the real engine runs on the restored default driver, so the rescue restarted Docker" '[ "$(docker_default_driver)" = json-file ]'
    systemctl daemon-reload
    return
}

cells_dk7() {
    cell_dk7_case "file created in this run" created '{}'
    cell_dk7_case "file merged in this run" merged '{"runtimes": {"nvidia": {"args": [], "path": "nvidia-container-runtime"}}}'
    cell_dk7_case "file merged by an earlier run, Docker still on json-file" earlier '{}'
    cell_dk7_case "Docker started but reports json-file" created '{}' wrong-driver
    engine_on_json_file_with ""
    at_terminal dk7-converge "$HAL_BIN setup"
    docker info >/dev/null 2>&1 || journalctl --unit docker --no-pager --lines 80 >"$EVIDENCE/dk7-docker-unit.txt" 2>&1
    return
}

cells_docker() {
    cell_dk2_merge
    cell_dk3
    cell_dk4_and_dk5
    cell_dk6
    cells_dk7
    return
}

cell_r5() {  # last: the rollback puts the package back, so nothing after it may expect it gone
    local conffile missing=() line="r5-probe-$$"
    apt-get update >"$EVIDENCE/r5-apt.log" 2>&1 && apt-get install --yes rsyslog >>"$EVIDENCE/r5-apt.log" 2>&1
    while read -r conffile; do
        [[ -e $conffile ]] || missing+=("$conffile")
    done <"$PACKAGE_CONFFILES"
    logger "$line"
    # The image's dpkg excludes /usr/share/doc and /usr/share/man, so those files are missing from every package here.
    dpkg --verify rsyslog 2>&1 | grep -v -e ' /usr/share/doc/' -e ' /usr/share/man/' >"$EVIDENCE/r5-verify.txt"
    verdict R5 "apt install rsyslog restores a package dpkg finds unchanged, and its conffiles (${missing[*]:-none missing})" \
        '[ -s "$PACKAGE_CONFFILES" ] && [ ! -s "$EVIDENCE/r5-verify.txt" ] && [[ ${#missing[@]} -eq 0 ]] && [ -e /etc/rsyslog.d/50-default.conf ]'
    verdict R5 "a logged line lands in /var/log/syslog" \
        'for _ in {1..30}; do grep -q "$line" /var/log/syslog 2>/dev/null && break; sleep 1; done; grep -q "$line" /var/log/syslog'
    return
}

# The sudo cells (P1-P10): the system step is one `sudo` call under each variant of the system's sudo, the classic one
# (suffix c) and sudo-rs (suffix r). Each cell asserts the active sudo first.
SUDO_CLASSIC=/usr/bin/sudo.ws
SUDO_RS=/usr/lib/cargo/bin/sudo
APPLY_ARGUMENTS="setup"

active_sudo_is() {  # active_sudo_is <alternative>
    local alternative=$1
    [[ $(readlink -f /usr/bin/sudo) == "$(readlink -f "$alternative")" ]]
    return
}

at_sudo_terminal() {  # at_sudo_terminal <log> <ticket: none|present> <hal args>: hal at a terminal, then the sudo ticket asked for in the same session
    # `sudo -k` first makes "none" true; "present" answers `sudo -v` first, counted apart from hal's prompts. `trap : INT` catches
    # Ctrl-C without ignoring it, so hal and sudo still get it and the shell survives to print TICKET=.
    local log=$1 ticket=$2 arguments=$3 preauth=""
    [[ $ticket == present ]] && preauth="sudo -v; "
    PROOF_PREAUTH=1 at_terminal "$log" \
        "trap : INT; sudo -k; ${preauth}echo @@HAL@@; $HAL_BIN $arguments; code=\$?; sudo -n true; echo TICKET=\$?; exit \$code"
    return
}

hal_prompts_are() {  # hal_prompts_are <log> <count> [<count before hal>]
    local log=$1 count=$2 count_before=${3:-}
    grep -qx "PROMPTS=$count" "$EVIDENCE/$log.log" && { [[ -z $count_before ]] || grep -qx "PREPROMPTS=$count_before" "$EVIDENCE/$log.log"; }
    return
}

ticket_is_gone() {  # ticket_is_gone <log>: the line is there and sudo -n failed
    local log=$1
    grep -qE '^TICKET=[1-9]' "$EVIDENCE/$log.log"
    return
}

no_become_prompt() {
    local log=$1
    ! grep -q 'BECOME password' "$EVIDENCE/$log.log"
    return
}

home_is_untouched() {  # the offenders are listed in the evidence
    find /home/tester -xdev \( -user root -o -name .ansible \) >"$EVIDENCE/home-offenders.txt"
    [[ ! -s "$EVIDENCE/home-offenders.txt" ]]
    return
}

ansible_tool_has_no_root_bytecode() {  # the offenders are listed in the evidence
    find /home/tester/.local/share/uv/tools/ansible-core -user root -name __pycache__ >"$EVIDENCE/ansible-bytecode-offenders.txt"
    [[ ! -s "$EVIDENCE/ansible-bytecode-offenders.txt" ]]
    return
}

cell_p_applies() {  # cell_p_applies <cell> <log> <ticket> <prompts>: a successful apply
    local cell=$1 log=$2 ticket=$3 prompts=$4 code announced=true
    at_sudo_terminal "$log" "$ticket" "$APPLY_ARGUMENTS"
    code=$?
    if [[ $prompts -eq 1 ]]; then
        announced="[ \"\$(grep -c '^  › system  *needs sudo' \"\$EVIDENCE/$log.log\")\" -eq 1 ] && announced_before_prompt $log"
    fi
    verdict "$cell" "apply succeeds, hal asks $prompts time(s), no BECOME, the ticket is gone" \
        "[ \$code -eq 0 ] && active_sudo_is \"\$sudo_alternative\" && hal_prompts_are $log $prompts && no_become_prompt $log && ticket_is_gone $log && row_in_log $log system '(changed|unchanged)' && $announced"
    return
}

cell_p_fails_in_the_play() {  # cell_p_fails_in_the_play <cell> <log> <ticket> <prompts>: the play fails after the password
    local cell=$1 log=$2 ticket=$3 prompts=$4 code
    cp /etc/cloudflared/config.yml /proof/config.yml.saved
    sed -i '/^tunnel:/d' /etc/cloudflared/config.yml
    at_sudo_terminal "$log" "$ticket" "$APPLY_ARGUMENTS"
    code=$?
    cp /proof/config.yml.saved /etc/cloudflared/config.yml
    verdict "$cell" "the step fails after $prompts prompt(s) and the ticket is gone" \
        "[ \$code -eq 3 ] && active_sudo_is \"\$sudo_alternative\" && hal_prompts_are $log $prompts && row_in_log $log system failed && ticket_is_gone $log"
    return
}

cell_p_interrupted() {  # cell_p_interrupted <cell> <log> <ticket>: Ctrl-C at the first task
    local cell=$1 log=$2 ticket=$3 code
    PROOF_INTERRUPT='TASK \[' at_sudo_terminal "$log" "$ticket" "$APPLY_ARGUMENTS"
    code=$?
    verdict "$cell" "Ctrl-C mid-play stops the step with 130 and the ticket is gone" \
        "[ \$code -eq 130 ] && active_sudo_is \"\$sudo_alternative\" && ticket_is_gone $log"
    return
}

cell_p_dry_run() {  # cell_p_dry_run <cell> <log> <ticket> <prompts>
    local cell=$1 log=$2 ticket=$3 prompts=$4 code
    at_sudo_terminal "$log" "$ticket" "setup --dry-run"
    code=$?
    verdict "$cell" "a dry run asks $prompts time(s), no BECOME, the ticket is gone" \
        "[ \$code -eq 0 ] && active_sudo_is \"\$sudo_alternative\" && hal_prompts_are $log $prompts && no_become_prompt $log && ticket_is_gone $log"
    return
}

cell_p_wrong_password() {  # cell_p_wrong_password <cell> <log>: sudo refuses three tries and the play never starts
    local cell=$1 log=$2 code before
    before=$(snapshot)
    PROOF_PASSWORD="not-the-password" at_sudo_terminal "$log" none "$APPLY_ARGUMENTS"
    code=$?
    verdict "$cell" "a wrong password: three prompts, hal fails, the play never started, /etc unchanged, the ticket is gone" \
        "[ \$code -eq 3 ] && active_sudo_is \"\$sudo_alternative\" && hal_prompts_are $log 3 && row_in_log $log system failed && ! grep -q 'PLAY \[' \"\$EVIDENCE/$log.log\" && [ \"\$before\" = \"\$(snapshot)\" ] && ticket_is_gone $log"
    return
}

cell_p_config_of_root() {  # cell_p_config_of_root <cell> <log>: root's own ansible.cfg does not override the packaged one
    local cell=$1 log=$2 code python package ansible_playbook=/home/tester/.local/bin/ansible-playbook outside inside
    python=$(head -n 1 "$HAL_BIN" | sed 's/^#!//')
    package=$(PYTHONDONTWRITEBYTECODE=1 "$python" -c 'import hal.workstation, pathlib; print(pathlib.Path(hal.workstation.__file__).parent / "system")')
    printf '[defaults]\nstdout_callback = json\n' >/root/.ansible.cfg
    outside=$(sudo env PYTHONDONTWRITEBYTECODE=1 sh -c "cd / && $ansible_playbook --version" 2>&1)
    inside=$(sudo env PYTHONDONTWRITEBYTECODE=1 sh -c "cd $package && $ansible_playbook --version" 2>&1)
    at_sudo_terminal "$log" none "$APPLY_ARGUMENTS"
    code=$?
    rm -f /root/.ansible.cfg
    verdict "$cell" "the recap is read although root's cfg selects json; the control shows which cfg wins where" \
        "[ \$code -eq 0 ] && active_sudo_is \"\$sudo_alternative\" && row_in_log $log system '(changed|unchanged)' && [[ \$outside == *'config file = /root/.ansible.cfg'* && \$inside == *'config file = $package/ansible.cfg'* ]]"
    return
}

cells_sudo() {  # cells_sudo <suffix> <alternative>: P1-P10 under one variant of sudo
    local suffix=$1 sudo_alternative=$2
    update-alternatives --set sudo "$sudo_alternative" >/dev/null
    verdict "P0$suffix" "the active sudo is $sudo_alternative" 'active_sudo_is "$sudo_alternative"'
    cell_p_applies "P1$suffix" "p1$suffix" none 1
    verdict "P1$suffix" "the operator's home holds no .ansible and no root-owned file" 'home_is_untouched'
    verdict "P1$suffix" "the ansible-core tool directory holds no root-owned __pycache__" 'ansible_tool_has_no_root_bytecode'
    cell_p_applies "P2$suffix" "p2$suffix" present 0
    cell_p_fails_in_the_play "P3$suffix" "p3$suffix" none 1
    cell_p_fails_in_the_play "P4$suffix" "p4$suffix" present 0
    cell_p_wrong_password "P5$suffix" "p5$suffix"
    cell_p_interrupted "P6$suffix" "p6$suffix" none
    cell_p_interrupted "P7$suffix" "p7$suffix" present
    at_sudo_terminal "p-converge$suffix" none "$APPLY_ARGUMENTS"
    cell_p_dry_run "P8$suffix" "p8$suffix" none 1
    cell_p_dry_run "P9$suffix" "p9$suffix" present 0
    cell_p_config_of_root "P10$suffix" "p10$suffix"
    return
}

case "${1:?stage}" in
    install) install_home ;;
    fresh) cell_dk1; plant_rsyslog_files; record_rsyslog_before; cell_11; cell_12; cell_13; cell_10; cell_r0; cell_dk3_before_the_first_apply; cell_1; cells_rsyslog_purged; cell_a1_1; cell_9; cell_a1_2; cell_r4; cell_s1; cells_yes; cells_mail; cells_agent; cells_docker; cells_retention; cells_polkit; marker_on ;;
    after-marker-reboot) cell_7; cell_a1_9; cell_r2_after_boot; marker_off ;;
    after-unmarked-reboot) cell_8; cell_r5 ;;
    prepared) wait_for_engine; prepare_today; cell_2 ;;
    sudo-classic) cells_sudo c "$SUDO_CLASSIC" ;;
    sudo-rs) cells_sudo r "$SUDO_RS" ;;
    shapes) at_terminal shapes-converge "$HAL_BIN setup"; cell_a1_3 ;;
    *) echo "unknown stage $1" >&2; exit 2 ;;
esac
