# home-tools

`hal` prüft den PC täglich, zeigt die Geheimnisse (`hal secrets`) und führt mit `hal setup` durch die fehlenden.
Jeder Befehl erklärt sich mit `hal <command> --help` samt Beispielen;
dieses README ist die lange Anleitung.

Alle Befehle teilen sich die Exit-Codes: `0` wenn alles sauber ist, `1` sobald
es einen Fund gibt (das ist kein Fehler — `hal-check.service` (von `hal setup`
geschrieben) trägt `SuccessExitStatus=1` dafür), `2` wenn das
Geheimnis-Manifest ungültig ist (`hal check` kennt zusätzlich die Konfigurationsdatei, siehe „Konfiguration“), `3` wenn ein Lauf an einem unerwarteten Fehler
zerbrach; dann steht eine `error:`-Zeile auf stderr. Bei `2` und `3` meldet der
Timer einen fehlgeschlagenen Dienst, zu Recht.

## hal check

```
hal check           # alle Prüfungen lesend, ein Bericht, höchstens eine Benachrichtigung und eine Mail
```

`hal check` fährt jede Prüfung, die nichts ändert — die Ansicht von
`hal secrets`, die Hook-Prüfung, die Log-Prüfung, die Backup-Prüfung, die Plattform-Prüfung und die Exposure-Prüfung (was von außerhalb dieses PCs erreichbar ist, dieselbe Suche wie `hal check exposure`; `hal` führt sie aus und reicht die Funde herunter) — und schreibt einen gemeinsamen
Bericht nach `~/.local/state/hal/check-report.md`; dort stehen die Zahlen und jeder Fund im Einzelnen.

Von Hand getippt liefert ein nacktes `hal check` Neuigkeiten aus wie der Timer: derselbe Bericht, dieselbe Mail und Benachrichtigung, dasselbe Merken der Funde; einen Probelauf ohne Zustellung gibt es nicht. Exit 0 sauber, 1 Funde, 2 Manifest oder `config.toml` sind ungültig (`error: <Datei>: …`), 3 ein Bereich konnte nicht prüfen, 130 unterbrochen; `--json` gehört nur zu `hal check exposure` und `hal check hosts` (Exit 2).

Auf dem Terminal steht davon eine englische Zeile je Bereich in der Reihenfolge der Mail (`ok`, `N action(s)`,
`N note(s)` mit dem Satz des ersten Funds und `+N more`, oder `not checked`) und ein Urteil, das sagt, ob eine Mail
rausging und wo der Bericht liegt; `next:` nennt den Schritt des ersten Handlungsbedarfs. Ein Bereich, der nicht
prüfen konnte, endet den Lauf mit `error:` und Exit 3.

**Stufen.** Jeder Fund hat genau eine Stufe. *OK*: nichts gefunden. *Note*: kann warten, nichts geht heute
kaputt, nichts liegt offen. *Action needed*: etwas ist jetzt kaputt, ungeschützt oder unsichtbar. Der Stand eines
Bereichs ist die schlimmste Stufe seiner Funde, der des PCs die schlimmste seiner sechs Bereiche (Services, Backup,
Commit protection, Secrets, Server logs, Exposure). Die Stufe und der Satz je Regel stehen in `RULE_REPORTS` in
`check.py`; ein Test lässt jede Regel der Prüfungen ohne Stufe scheitern.

| Prüfung | Action needed | Note |
|---|---|---|
| `platform` | `container-restarting`, `container-dead`, `container-unhealthy`, `container-exited`, `docker-unreadable`, `job-failed`, `systemd-unreadable`, `disk-low` | `reboot-pending` |
| `backup` | `backup-stale`, `backup-failed`, `backup-status-unreadable`, `backup-crashed` | – |
| `hook` | `hooks-path`, `hook-file`, `quality`, `mise`, `engines` | `hidden-hook` |
| `secrets` | `loose-mode`, `symlinked-folder`, `symlinked-file`, `revocation-unconfirmed`, `verification-failed`, ein fehlendes Passwort eines Menschen (`SecretKind.HUMAN_PASSWORD`, als Regel `missing-password` gemerkt) | `missing` (sonst), `not-a-folder`, `closed-folder`, `presence-unknown`, `verification-unreachable`, `unknown-file` |
| `logs` | `journal-age`, `journal-unreadable`, `docker-unreadable` | `container-json-file`, `docker-default-driver`, `rsyslog-file` |
| `exposure` | `reachable-beyond-loopback` (Veröffentlichung oder Listener jenseits von Loopback, ein Fund je Prozess oder Container), `routing-name-unusable` (`routed-without-edge-name`, `invalid-edge-name`, `duplicate-edge-name`) | – |

Ein zerbrochener Lauf einer Prüfung ist Action needed („The … check did not run“, Schritt `hal check`); bei Exposure ist das auch Docker nicht erreichbar, `ss` fehlt oder die Erlaubnisliste unlesbar. Der Scan läuft als du, ohne sudo, und braucht bis zu 90 s (zwei `docker`-Aufrufe und `ss`, je 30 s).

Die Funde von Exposure ändern sich mit ihrem Gegenstand, nicht mit dem Port: Wandert sshd von 22 auf 2222, kommt keine Mail; der Bericht zeigt jede Zeile des Scans.

**Wann gemeldet wird.** Eine Desktop-Benachrichtigung (über `notify-send`, falls installiert) und eine Mail kommen nur,
wenn eine Action-needed-Stufe neu auftaucht oder verschwindet, auch wenn danach nichts mehr übrig ist; ein zerbrochener oder
wieder laufender Lauf einer Prüfung ist so einer. Ändern sich nur Notes, kommt nichts. Ein Fund ist Regel plus
Gegenstand: Derselbe Fund, der nur älter oder größer wird, nervt nicht erneut; wechselt ein Container von „startet
neu“ zu „beendet“, ist das ein neuer Punkt.

Betreff und Titel der Benachrichtigung sagen den Stand des PCs in einem Satzteil: „PC check: action needed –
Services, Backup“ (mit den Bereichen im Action needed), „PC check: all well – notes only“ oder „PC check:
all well“. Der Text der Benachrichtigung sind die Sätze der Action-needed-Funde und der Pfad des Berichts. Die
Benachrichtigung trägt den Knopf „Open report“; ein Klick öffnet den
Bericht mit `xdg-open`. Gewartet wird nicht im Check, sondern in einer
losgelösten Einheit (`systemd-run --user --collect`), sodass `hal check` und
der Timer-Dienst sofort enden.

Die zuletzt gemeldete Fundmenge hält `~/.local/state/hal/check-findings.txt`. Der saubere Stand wird ebenfalls
gemerkt, sodass ein wiederkehrender Action-needed-Fund wieder meldet. Scheitert eine fällige Benachrichtigung, bleibt die
zuletzt gemeldete Fundmenge stehen, und der nächste Lauf meldet, was dann noch von ihr abweicht.

**Die Mail.** Sie geht über `msmtp`, als du, mit dem Konto aus `~/.secrets/smtp/account.toml`, und nur, wenn diese Datei
existiert; fehlt sie, schickt `hal check` nichts und meldet keinen Fehler (der Tagesbericht listet die fehlenden
Einträge). Der Text hat oben jeden Fund mit Action needed als Satz mit genau einem nächsten Schritt (neue Punkte mit „(new)“,
höchstens 20, dann „… and N more, see report“), darunter was nicht mehr ansteht, dann eine Zeile je Bereich und
den Pfad des Berichts:

```
Subject: PC check: action needed – Services

Action needed

1. presentator-live keeps restarting and is therefore unreachable. (new)
   Next step: Tell an agent: "presentator-live keeps restarting, please look".

How the PC stands (2026-10-26 14:54)

Services: Action needed
Backup: OK, last backup today 14:15
Commit protection: OK
Secrets: Note – Credentials for hopin are still missing
Server logs: OK
Exposure: OK

Notes are not urgent.
Everything in detail: ~/.local/state/hal/check-report.md
```

Keine Zahl, nie ein Wert, Name oder Pfad eines Geheimnisses, nie eine Datei aus dem Home: Genannt werden nur das Compose-Projekt eines
Containers oder Prozesses, bei Exposure der Name des Containers, Prozesses oder der Unit (nie Adresse, Port, Protokoll oder Erlaubnisliste), Apps (aus `read_by` des Manifests, nur einfache Namen wie `hopin`) und der Zeitpunkt der letzten Sicherung; bei Geheimnissen, Commit-Schutz und Logs steht nur, was los ist. Ein
ungültiges Konto schickt nichts und nennt Schlüssel und Regel auf stderr, nie den Wert.

**Welcher Kanal zählt.** Der Desktop zählt nur, solange eine grafische Sitzung läuft (`systemctl --user is-active
graphical-session.target`, nur geprüft, wenn es etwas zu melden gibt), die Mail, solange das Konto existiert. Jeder
eingerichtete Kanal wird versucht; scheitert einer, steht eine Zeile auf stderr, der Exit-Code bleibt, und die gemeldete
Fundmenge rückt nicht vor, sodass der nächste Lauf erneut meldet. Sie rückt vor, wenn jeder eingerichtete Kanal
geliefert hat: ein Lauf ohne Sitzung (Linger, 09:00) mit gelieferter Mail genügt. Ohne einen einzigen eingerichteten Kanal
bleibt sie stehen, ohne Ausgabe. `[check] notify = false` schaltet beide ab.

Zerbricht eine Prüfung (etwa ein Ordner unter `~/.secrets`, den `hal` nicht
lesen darf), steht an ihrer Stelle eine Zeile „check secrets failed
(…)“, die Funde der anderen Prüfung bleiben im Bericht, die Benachrichtigung
geht trotzdem raus, und der Lauf endet mit Exit-Code `3` — bei einem
ungültigen Geheimnis-Manifest mit `2`, und stderr nennt Datei und Schlüssel.

### Die Prüfung `hook`

Git lässt einen Commit ungescannt durch, wenn der Hook-Pfad abdriftet. Die
Prüfung `hook` fragt `setup.py` nach dem Soll und meldet je Fund die
Korrektur:

- **Hook greift nicht.** In jedem Repository unter `~/git` und jedem seiner
  registrierten Worktrees (auch außerhalb von `~/git`) muss das wirksame
  `core.hooksPath` das Hook-Verzeichnis sein und aus der globalen Config selbst
  stammen (`~/.gitconfig` oder `$XDG_CONFIG_HOME/git/config`). Der Ursprung entscheidet,
  nicht der Scope: lokale Config, Worktree-Config, System-Datei, `include` und
  `includeIf` sind Funde, ebenso ein ungesetzter Wert. Die Korrektur nennt den
  passenden Weg (`git config --local --unset`, `--worktree --unset`, die
  genannte Datei bearbeiten oder `hal setup`).
- **Hook-Datei falsch.** `pre-commit` oder `pre-merge-commit` fehlt, hat nicht den Modus 755
  oder weicht vom gerenderten Text ab (`hal setup`).
- **quality nicht wie festgelegt.** `~/.local/bin/quality` fehlt, ist nicht ausführbar oder uv hat
  nicht `QUALITY_SOURCE` aufgezeichnet (`hal setup`).
- **mise nicht wie festgelegt.** `~/.local/bin/mise` fehlt, ist nicht ausführbar oder sein sha256 weicht
  von `MISE_SHA256` ab (`hal setup`); der Bericht nennt es als eigene Aufgabe, nicht als kaputten Commit-Schutz.
- **Engines.** `quality engines verify` scheitert (`hal setup`).
- **Verdeckter Repository-Hook.** `.git/hooks` enthält eine Datei außer
  `*.sample`, `pre-commit` und `pre-merge-commit`; der globale Pfad verdeckt sie.

Was die Prüfung nicht sieht, weil es flüchtig ist oder außer Reichweite liegt:

- ein einzelner Befehl mit `-c core.hooksPath=…`, `GIT_CONFIG_PARAMETERS`,
  `GIT_CONFIG_COUNT` oder `GIT_CONFIG_GLOBAL`;
- `--no-verify`;
- Repositories außerhalb von `~/git`;
- ein `includeIf "onbranch:…"`, das nur für den Branch gilt, der beim Lauf von
  `hal check` ausgecheckt ist.

Kann die Prüfung nicht laufen (git lässt sich nicht starten), gilt sie als
zerbrochen, nie als sauber.

### Die Prüfungen `backup` und `platform`

Beide lesen nur und ändern nichts. Was sie lesen, ist fest: nie ein Container-Log, nie die Umgebung eines Containers, nie
`~/.secrets` oder `~/backups`. Der Bericht trägt nur Namen, Zustände und Zeiten. Ein Fund ist Regel
plus Gegenstand (Containername, Appname); sein Alter gehört nie dazu. Lässt sich die Quelle nicht lesen, ist das ein
eigener Fund, nie ein sauberer Lauf.

- **`platform`, Container.** Jeder Container mit nicht leerem Compose-Projekt-Label (`docker inspect --format` mit
  benannten Feldern, darunter das Projekt, ein Aufruf für alle; der Fund trägt den Projektnamen): `container-unhealthy`, `container-restarting`, `container-dead` und
  `container-exited` mit Code ungleich 0 (alle Action needed). Exit-Code 0, `starting` und ein Container ohne Healthcheck sind keine Funde,
  ein entfernter Container auch nicht. Gesunde erscheinen nur als Zahl. Ein Container einer App, die mit `hal stop`
  abgeschaltet ist (eine Datei unter `~/.local/state/edge/stopped/`; nur der Name wird gelesen), ist mit jedem Code ungleich 0
  kein Fund, und der Bericht nennt die Schalter; `container-restarting`, `container-dead` und `container-unhealthy` bleiben
  Funde. Eine Einheit von edges eigenem Stack (Projekt `edge`) erscheint nach `hal stop` weiter, weil nur `hal` weiß, welche Dienste eine Einheit bilden und dafür noch niemand zuständig ist; `hal alarm` meldet sie deshalb nach der eingestellten Zahl Läufe. `docker-unreadable`, wenn Docker nicht lesbar ist.
- **`platform`, Jobs.** `systemctl --user list-units --state=failed` für `hal*`: nur die erste Spalte, der Einheitenname
  (`hal-backup.service`), wird gelesen, nie die Beschreibung. Jede fehlgeschlagene `hal*`-Einheit ist ein `job-failed`
  (Action needed, Gegenstand der Name samt Endung); sie verschwindet mit `reset-failed` oder einem erfolgreichen Lauf. Passt ein Name nicht
  zur Namensform oder lässt sich systemd nicht lesen, ist das `systemd-unreadable`. Der Lauf von `hal-check.service` sieht seinen eigenen
  vorigen Fehler nicht, weil ein Start den Fehlerzustand löscht.
- **`platform`, Neustart.** `/var/run/reboot-required`: nur Dasein und Änderungszeit (`reboot-pending`, „seit
  Datum“); ein Fund der Stufe Note, der nie eine Mail auslöst.
- **`platform`, Festplatte.** Nur die Platte, auf der `/` liegt (`shutil.disk_usage`: was ein unprivilegierter Prozess
  noch nutzen kann): `disk-low` (Action needed), wenn weniger als 10 % frei sind; genau 10 % ist kein Fund. Der Fund
  hat den Gegenstand `/`, der freie Platz gehört nicht zur Identität. Die Mail nennt keine Zahl, der Bericht GB frei,
  GB gesamt und den Anteil. Lässt sich die Platte nicht lesen, läuft die Prüfung `platform` nicht.
- **`backup`.** `~/.local/state/edge/backup-status.json` (Schema 2, nur die dokumentierten Felder): `backup-failed`,
  wenn der letzte Lauf `failed` ist; `backup-crashed`, wenn `running` länger als 6 Stunden her ist; `backup-stale` je
  App, wenn `last_successful_backup` älter als 8 Tage ist oder fehlt; `backup-status-unreadable`, wenn die Datei
  fehlt, nicht lesbar ist (ein Symlink an ihrer Stelle wird nicht verfolgt), ein anderes Schema oder einen Wert außerhalb
  seiner dokumentierten Werte hat. Die 8 Tage und 6 Stunden sind Konstanten in `backup_check.py`.

### Die Prüfung `logs`

Auf diesem PC gilt für jedes Server-Log die Grenze von 30 Tagen
(`LOG_RETENTION_DAYS` in `system_step.py`). Die Prüfung `logs` berichtet Alter
und Treiber jedes Speichers, liest nie einen Nachrichtentext und ändert nichts:

- **Container mit `json-file`.** Jeder Container in jedem Zustand, dessen
  Log-Treiber `json-file` ist, mit Namen und Compose-Projekt. `journald` und
  `none` sind keine Funde.
  Jeder Einmal-Container von edge (`keycloak-config-cli`, `realm-observer`,
  `agent-smoke`, die Einmal-Container von `step-ca/init` und der Sicherung, die
  Listener-Probe) startet mit Treiber `none`: Seine Ausgabe gehört allein dem
  Aufrufer und gelangt nicht ein zweites Mal ins Journal.
- **Docker-Standardtreiber** (`docker info`) außer `journald`.
- **Journal zu alt.** Der älteste Eintrag laut `journalctl --list-boots -o json`
  (Zeiten der Boots, nicht der Meldungen) ist älter als `LOG_RETENTION_DAYS`.
- **rsyslog-Dateien.** `syslog`, `auth.log`, `kern.log`, `mail.log`, `mail.err`
  und `ufw.log` samt Archiven unter `/var/log`, nur nach Name und Dasein. Der Fund
  heißt: rsyslog ist zurück (etwa durch ein Paket-Update); der nächste
  `hal setup` entfernt es und die Dateien wieder.

Lässt sich `docker` oder `journalctl` nicht ausführen oder liefert das Journal
kein lesbares Ergebnis, ist das ein eigener Fund (`docker-unreadable`,
`journal-unreadable`), nie ein sauberer Lauf. Das gilt auch für eine
Teilansicht: Ohne Leserecht auf das Systemjournal (`journalctl --system`) sähe
`journalctl` nur das Journal des Benutzers und meldete dennoch Erfolg; die
Prüfung liest deshalb beide Ansichten und nennt die fehlende als Fund. Ein
Container, der zwischen `docker ps` und `docker inspect` verschwindet, gilt als
weg, nicht als Fehler. Der Bericht nennt außerdem je
Speicher den Stand (Journal-Alter, Standardtreiber, Zahl der Container).

## hal secrets

```
hal secrets                # was Aufmerksamkeit braucht, die gesunden Einträge gezählt; nie ein Wert
hal secrets -v             # jeder Eintrag als Tabelle, jeder Fund einzeln mit seinem Schritt
hal secrets --by-service   # welcher Dienst welches Geheimnis liest (deklariert)
```

`hal secrets` prüft jedes Geheimnis, das das Manifest
`src/hal/workstation/secrets_manifest.toml` nennt, und ändert nichts außer seinem
Bericht `~/.local/state/home/secrets-report.md`. Es braucht kein Terminal;
Agenten dürfen es fahren. Einrichten geht nur mit `hal setup` (unten);
eine Option dafür hat `hal secrets` nicht, ein unbekanntes Argument endet mit Exit 2. Exit-Code: `0` sauber, `1` Funde, `2` das Manifest ist ungültig
(`error: <Datei>: …`), `3` ein unerwarteter Fehler, `130` unterbrochen.

**Kein Wert, nirgends.** Das Manifest enthält nur Namen, Orte und Links.
`hal secrets` liest Geheimnisdateien nur per `stat` und öffnet sie nie. Die
einzige Prüfung der Ansicht ist `gh auth status` (der Keyring-Login von `gh`): `hal`
behält davon nur den Exit-Code, verwirft Ausgabe und Fehlerausgabe und bricht
nach 20 Sekunden ab.

Das Terminal zeigt Zeilen im Format der übrigen Befehle (Beispiel, gekürzt): je Fund eine
`!`-Zeile mit dem einen Schritt darunter, dann eine `✓`-Zeile für alle vorhandenen Einträge ohne
Fund, eine `·`-Zeile für fehlende optionale und eine für zurückgezogene mit bestätigtem Widerruf, am
Ende das Urteil, das jeden Fund zählt. Ab sechs Fund-Zeilen teilen sich Datei- und Ordnerfunde mit
gleicher Regel, gleichem Ordner und gleichem Befund eine Zeile (bis drei Pfade mit Namen, sonst
ihre Zahl) ohne Schritt; `-v` bündelt nie.

```
  ! cloudflared/old.json  unknown        not in the manifest
    add ~/.secrets/cloudflared/old.json to the manifest or delete it
  ! gmail-cleanup   too open       has mode 775; at most 700 allowed
    chmod 700 ~/.secrets/gmail-cleanup
  ✓ 4 entries       present        gh checked: valid; the rest not checked
  · 1 optional      not set up     ssh/id_ed25519.ppk
  · 1 retired       revoked        github/token
! 2 findings · hal secrets -v lists every entry
```

`hal secrets -v` druckt stattdessen eine ausgerichtete Tabelle mit den Spalten `name`, `kind`,
`file`, `check`, `place` und `renew`, darunter jeden Fund einzeln und das Urteil ohne Hinweis.

Der Bericht `secrets-report.md` bleibt Markdown, Byte für Byte: `hal check` und seine Mail lesen
ihn. Beispiel (gekürzt):

```
# hal secrets 15.10.2026 09:00 | 2 findings

| Name | Kind | File | Check | Expiry | Place | Recreate |
|---|---|---|---|---|---|---|
| gitlab | token | present | not checked | expiry unknown | ~/.secrets/gitlab | https://code.siemens.com/-/user_settings/personal_access_tokens |
| gh | tool login | present | checked: valid | expiry unknown | ~/.config/gh | `gh auth login --web` |
| secrets/README | documentation | present | not checked | expiry unknown | ~/.secrets/README | ~/.secrets/README anlegen: je Datei eine Zeile, was sie ist (kein Geheimnis) |
| cloudflared | tool login | present | not checked | expiry unknown | ~/.secrets/cloudflared/cert.pem; Tunnel-Config und Zugangsdatei des laufenden Tunnels: /etc/cloudflared (root) | `cloudflared tunnel login` im Browser |
| ssh/id_ed25519.ppk | derived copy | missing (optional) | not checked | expiry unknown | ~/.ssh/id_ed25519.ppk | `puttygen ~/.ssh/id_ed25519 -o ~/.ssh/id_ed25519.ppk` |
| github/token | token | retired | revocation confirmed 15.10.2026 | expiry unknown | ~/.secrets/github/token | revoke: https://github.com/settings/tokens |

## Findings

| Rule | Subject | Finding | Fix |
|---|---|---|---|
| unknown-file | ~/.secrets/cloudflared/old.json | - | add ~/.secrets/cloudflared/old.json to the manifest or delete it |
| loose-mode | ~/.secrets/gmail-cleanup | has mode 775; at most 700 allowed | `chmod 700 ~/.secrets/gmail-cleanup` |

No values: hal secrets reads secret files by stat only and never opens them.
```

So liest sich die Tabelle des Berichts (und, ohne Expiry, die von `-v`):

| Spalte | Werte |
|---|---|
| Kind | human password, tool login, token, service password, „token, unverified“, derived copy — genau eine je Eintrag; `configuration` und `documentation` für bekannte Dateien unter `~/.secrets`, die kein Geheimnis sind |
| File | `present`, `missing`, `unknown` (das Dateisystem verweigert die Auskunft), `retired`; ein optionaler Eintrag trägt `(optional)` |
| Check | bei einem zurückgezogenen Eintrag `revocation unconfirmed` oder `revocation confirmed <Datum>` |
| Place | die Pfade im Home; liegen Kopien woanders (etwa `/etc/cloudflared`, root), nennt sie die Zelle dahinter, gelesen werden sie nie |
| Check | nur `gh` wird geprüft (`checked: valid`, `checked: invalid`, `check not possible` bei Zeitüberschreitung oder fehlendem `gh`); alle anderen `not checked` |
| Expiry | heute immer `expiry unknown`: ein Datum erscheint erst mit Herkunft (Antwort des Anbieters oder ein vom Assistenten geschriebenes `rotated_on`); das Dateialter zählt nie |

Funde sind: ein fehlender Eintrag (außer einem optionalen) oder ein unbekannter, ein zurückgezogenes
Geheimnis, dessen Widerruf unbestätigt ist, eine fehlgeschlagene oder nicht
mögliche Prüfung, eine Datei oder ein Ordner unter `~/.secrets`, den kein
Eintrag nennt („unknown“; bleibt unangetastet), und Rechte lockerer als
`600` für Dateien oder `700` für Ordner unter `~/.secrets`, ein Ordner dort,
den sein Besitzer nicht lesen, betreten oder beschreiben kann („closed-folder“;
was darin liegt, ist „unknown“), ein Symlink
auf dem Weg zu einem Eintrag („symlinked-folder“; die Empfehlung ersetzt ihn durch
den Ordner, auf den er zeigt, oder durch einen leeren, wenn das Ziel fehlt), ein Symlink
an der Stelle eines Eintrags unter `~/.secrets` (er zählt als fehlend; „symlinked-file“; die
Empfehlung entfernt mit `rm` nur den Link und lässt sein Ziel unangetastet) und eine Datei, wo auf dem Weg zu einem Eintrag ein
Ordner stehen muss („not-a-folder“; die Empfehlung schiebt sie mit `mv -n` nach
`<Name>.alt`). Die Ordner auf dem Weg beurteilt dieselbe Regel, mit der
der Assistent das Speichern verweigert. `hal` setzt nie Rechte und ersetzt nichts;
`chmod` bleibt ein Handgriff.

### Einrichten: `hal setup`

`hal setup` hat dafür den Schritt „Geheimnisse“: Er gilt als erledigt, wenn das Manifest
auf diesem PC kein offenes Geheimnis hat (nur `stat`); offen ist auch ein Eintrag, dessen
Vorhandensein sich nicht feststellen lässt. Mit `--dry-run` nennt er die offenen in der Zeile
`! secrets  missing  a, b (by hand), c (unknown)` und ändert nichts; nach dem yes zeigt `hal setup` vor dem Assistenten `! secrets  N missing  a, b` und führt ihn dann aus; er braucht ein eigenes Terminal. Er ist der einzige
Weg zum Assistenten; `hal secrets` zeigt nur. Ein Eintrag mit
`loosest_mode` landet mit diesem Modus (0644) in seinem 0700-Ordner, alle anderen mit 0600.

Der Assistent geht die fehlenden Einträge des Manifests der Reihe nach durch,
zuerst die fünf der Publish-Phase von `hal apply`. Gelesen werden davon drei:
`cloudflare/fleet-read` und `opentofu/state-passphrase` zuerst, danach
`cloudflare/fleet-write`. `github/fleet-read` und
`github/fleet-admin` bleiben im Assistenten, aber nichts liest sie, bis
edge#30 X2/X3 die GitHub-Einstellungen als Code bauen. Es läuft nur am
eigenen Terminal (stdin und stdout); ohne Terminal fragt `hal setup` kein yes und endet nach dem Plan mit Exit-Code `4`;
der Assistent läuft erst nach dem yes. Agenten fahren ihn nie.

Ein Token legt nur an, wer mehr Rechte hat als das Token: GitHub hat für
Fine-grained-Tokens keine API, und für Cloudflare bräuchte der Assistent
einen Admin-Schlüssel auf der Platte. Den Login im Browser macht deshalb der
Mensch, alles andere der Assistent. Je Token:

1. Er sagt, was kommt: eine Zeile `›` mit dem Eintrag und `new token`, darunter `why:` (wofür) und die
   Checkliste der Rechte. Ein erzeugter oder von Hand anzulegender Eintrag druckt nur seine Ergebniszeile.
   Vorher prüft er die Ordner auf dem Weg: Ist einer lockerer als `700`, für
   seinen Besitzer verschlossen, ein Symlink („is a symlink“) oder kein
   Ordner, oder steht an der Stelle selbst ein Symlink (Befehl: `rm`, nur der
   Link), nennt er das mit dem Befehl, der es behebt, und öffnet keine Seite,
   damit kein frisch angelegtes Token verloren geht.
2. Nach Enter öffnet er die Seite. GitHubs Formular ist über die dokumentierten
   URL-Parameter vorausgefüllt (Name, Resource owner `overnightworks`, Ablauf,
   Beschreibung, Rechte); „Repository access: All repositories“ kann kein Link
   setzen und steht als Haken in der Liste. Cloudflare füllt nichts vor; die
   Liste nennt jede Permission, die Zone und das TTL-Enddatum; das Startdatum
   bleibt leer.
3. Er nimmt den Wert unsichtbar entgegen. Leer lassen überspringt den Eintrag.
4. Er fragt den Anbieter, bevor er speichert: Cloudflare
   `GET /user/tokens/verify` muss `active` melden und darf kein Startdatum
   (`not_before`) in der Zukunft haben, GitHub muss
   `GET /orgs/overnightworks/actions/secrets` beantworten (das braucht die
   Org und das Secrets-Recht und liefert nur Namen). Ein abgelehnter Wert wird
   mit einer Zeile abgewiesen und nicht geschrieben; danach darf man noch
   einmal einfügen.
5. Er schreibt die Datei mit `600` in einen Ordner mit `700` und geht zum
   nächsten Eintrag. Die Ordner prüft er dabei noch einmal; `hal` setzt keine
   Rechte.

Die State-Passphrase erzeugt er zufällig und schreibt sie, ohne sie zu zeigen.
Key-ID und API-Token des TURN-Keys, den nur HopIn nutzt (`cloudflare/turn-hopin/key-id` und
`…/api-token`, Art „token, unverified“), nimmt er ebenso unsichtbar entgegen, nennt vorher, wo
der Key entsteht (Cloudflare › Realtime › TURN, beide Werte zeigt Cloudflare nur einmal), und
bietet die Cloudflare-Startseite an. Er speichert sie ohne Prüfung durch einen Anbieter (`stored`, `not verified`), denn der TURN-Token ist kein Benutzer-Token, und kein Anbieter wird gefragt; `hal secrets`
zeigt beide als `not checked`. Ob Cloudflare sie annimmt, zeigt erst HopIn beim Start.
Ebenso nimmt er den Provider-Key für Anthropic entgegen (`litellm/anthropic`, nur `litellm` liest ihn):
Er nennt, wo der Key entsteht (die Console, im Workspace mit dem Guthaben; Anthropic zeigt ihn nur einmal),
und bietet die Seite der API-Keys an. Er schickt den Key nirgends hin, also prüft ihn kein Anbieter. Der Eintrag ist nicht
`optional`; bis er eingefügt ist, bleibt `hal secrets` bei `missing litellm/anthropic`.
Eine vorhandene Datei bleibt unangetastet; ersetzen ist `--rotate` und kommt
später. Ein Eintrag ohne Assistent (etwa `gitlab`) wird mit seiner Seite aus
`recreate` genannt (`by hand`), ein optionaler, der fehlt, übersprungen (`skipped`, `optional`). Strg-C bricht ab, ohne eine halbe Datei zu hinterlassen
(Exit-Code `130`); der nächste Lauf macht beim ersten fehlenden Eintrag weiter.
Der Assistent druckt kein eigenes Ende; den Ausgang nennt `hal setup` mit seiner `secrets`-Zeile und seinem Urteil.

Jeder Fall druckt eine Zeile `Zeichen Name Ereignis Tatsache` (Ereignisse: `verified`,
`generated`, `stored`, `rejected`, `skipped`, `not checked`, `by hand`, `not stored`, `new login`,
`signed in`, `not signed in`); ein Eintrag, der
schon da ist, druckt keine. Nie steht ein Wert in einer Zeile, nur Name, Pfad und Rechte. Ein TURN-Wert
endet mit `✓ cloudflare/turn-hopin/key-id  stored  not verified · ~/.secrets/cloudflare/turn-hopin/key-id (644)`.

Beispiel (gekürzt, ein abgelehnter Versuch):

```
  › github/fleet-read  new token  the link fills name, owner, expiry and rights
    why: Nothing reads it today; hal apply needs it again once edge#30 X2/X3 builds the GitHub settings as code (repo settings, rulesets, Actions rules, org secret names, never their values). The file stays, nothing is revoked.
    prefilled: Metadata read, Organization secrets read
    [ ] Repository access: All repositories
    [ ] compare the rights in the form with the line above
    [ ] Generate token, copy the value
    Enter opens the page in your browser:
    opened github.com/settings/personal-access-tokens/new?…
    paste the token (hidden, empty skips):
  ✗ github/fleet-read  rejected  GitHub answers 401 · paste again or leave empty
    paste the token (hidden, empty skips):
  ✓ github/fleet-read  verified  ~/.secrets/github/fleet-read (600)
  ✓ opentofu/state-passphrase  generated  ~/.secrets/opentofu/state-passphrase (600) · never shown
```

`opened` zeigt Host und Pfad der Seite, bei einer Abfrage mit `?…`; öffnet kein Browser die
Seite, steht die ganze Adresse in der gelben Zeile `no browser opened`.

Ist alles gespeichert, folgt dem Urteil von `hal setup` die Zeile
`next: hal apply`; es zeigt den Plan vor seinem Ja. Allein gefahren endet
der Assistent mit der letzten Eintragszeile und dem Exit-Code. Exit-Code: `0` nichts fehlt mehr,
`1` es fehlt noch etwas, `2` ein Terminal, das die Eingabe nicht
verbergen kann, Manifest ungültig oder ein unerwarteter Fehler bei einem
Eintrag, `130` abgebrochen. Strg-C und das Ende der Eingabe nennen den Eintrag, an dem sie trafen.
Ein unerwarteter Fehler nennt nur seine Art und den Eintrag, nie seine
Meldung, denn die könnte einen Wert zitieren, dazu, ob dieser
Eintrag danach gespeichert ist, und `hal setup` zum Weitermachen;
vorher gespeicherte Einträge bleiben.

`--by-service` dreht `read_by` des Manifests um: je Dienst die Geheimnisse,
die er laut Manifest liest, dazu die abgeleiteten Kopien und ihre Quelle. Die
Überschrift sagt „declared dependencies“: Das ist, was das Manifest
behauptet, kein Beweis vollständiger Wirkung.

### Einen Eintrag hinzufügen

Ein neues Geheimnis ist ein Block im Manifest:

```toml
[[secret]]
name = "grafana-admin"
kind = "service-password"
paths = ["~/.secrets/grafana/admin"]
read_by = ["grafana.service"]
recreate = "wird beim Einrichten erzeugt"
```

`paths` beginnt mit `~/`, nur der letzte Teil darf einen Platzhalter tragen
(`~/.secrets/cloudflared/*.json`). Ein zurückgezogener Eintrag trägt
`retired_on = 2026-10-14` und `revoke_url`, nach geprüftem Widerruf auch
`revocation_confirmed = 2026-10-15`; eine abgeleitete Kopie trägt
`mirror_of`. `optional = true` heißt: Fehlen ist kein Fund, der Assistent
überspringt den Eintrag; so stehen auch die bekannten Dateien ohne Geheimnis
(`~/.secrets/README`, `claudebot-runtime.env`) im Manifest. `elsewhere` nennt Kopien außerhalb des Homes für die
Spalte „Place“. `purpose` sagt in einem Satz, wofür es da ist. `loosest_mode`
(ein TOML-Oktalwert wie `0o644`) erlaubt den Dateien eines Eintrags ein lockereres
Höchstmaß als 0600, weil ein Container-Nutzer sie lesen muss; `loosest_mode_reason`
sagt in einer Zeile, wer sie liest, und gehört dazu. Mehr als 0644 lehnt das
Laden des Manifests ab. Die Prüfung misst die Datei dann an diesem Maß und
empfiehlt nie ein engeres. Ein Token, durch
das der Assistent führt, nennt dazu `provider` (`github` oder `cloudflare`),
`resource` (GitHub: der Resource owner; Cloudflare: die Zone), `scope` (die
Rechte; bei GitHub als `<URL-Parameter>:read|write|admin`) und
`expires_in_days` (1 bis 366), alle vier zusammen; ein `unverified-token` nennt keinen davon, dafür `page`
(eine `https://`-Adresse, die der Assistent zum Öffnen anbietet; kein anderer Eintrag nennt sie), und hat
genau einen Pfad: der Assistent fragt seinen Wert unsichtbar ab und speichert ihn ungeprüft; ein `service-password`
hat genau einen Pfad ohne Platzhalter und wird erzeugt, außer er ist `optional`:
dann schreibt ihn die Einheit aus `recreate`. Ein `tool-login` kann statt eines `recreate` ein `create` nennen (nur mit `purpose`; beides zusammen lehnt das Laden ab)
(`run`: die CLI, `home`: die Variablen, die sie auf den Ordner des Eintrags zeigen lässt, `label`: das
Konto, wie der Mensch es nennt); ein solcher Eintrag hat genau einen Pfad ohne Platzhalter: der Assistent lässt die CLI im
Browser anmelden (`new login`, danach `signed in` mit Pfad und Rechten, oder `not signed in` mit dem Grund),
setzt den Ordner auf 0700 und die Anmeldedatei auf 0600 und liest sie nie; was die CLI daneben ablegt, gehört zum Eintrag (nie unbekannt, nie auf den Modus geprüft, durch den Ordner 0700 geschützt); bei einem Fehlschlag löscht er, was die CLI
hinterließ, und der nächste Lauf fragt wieder. `hal secrets` zeigt als Erneuerung den aus `create`
abgeleiteten Befehl. Ein unbekannter Schlüssel (auch ein Versuch, einen Wert
abzulegen), ein falscher Wert oder ein doppelter Name lässt `hal secrets`
mit Exit-Code `2` abbrechen; die Meldung nennt Datei und Schlüssel.

## hal setup

Richtet den globalen Commit-Hook gegen Geheimnisse ein.
Then it links `~/.local/bin/hal` to the `bin/hal` of the live checkout, whichever tree runs `hal setup` (the `path` row: it creates a missing link,
re-points a link into another hal checkout, such as a clone that has moved, and refuses to replace a file, a directory or a link into anything else).
Then it writes hal's user units and runs the system step.
`hal setup` zeigt den Plan, fragt `Type yes to set up N open rows:` (`hal.output.confirmed`: nur genau `yes`,
Ende der Eingabe heißt nein, Strg-C wird nicht gefangen) und führt es erst danach der Reihe nach aus; es hält beim ersten Fehler an.
`hal setup --dry-run` zeigt nur, überspringt das yes und ändert nichts (an einem Terminal fragt sudo trotzdem, um `system` zu prüfen). Vor dem yes liest und ändert `hal setup` nichts mit Root: die Zeile `system` steht im Plan
als `! system  not checked  sudo checks it after your yes` und zählt als offen. Both print five rows (below) and a verdict.
Exit: 0 fertig oder nichts offen, 1 abgelehnt (`error: aborted, nothing changed`), 3 ein Schritt ist gescheitert (auch eine Prüfung des Plans, ohne Frage), 4 braucht ein Terminal
(`error: setup asks yes at a terminal · nothing changed`, `next: hal setup in your own terminal window`; der Plan steht, kein Schritt läuft), 130 unterbrochen.
Ist nichts offen, fragt es nicht und braucht kein Terminal (das trifft nur das Konto des Agenten). `--apply` gibt es nicht: `error: unrecognized arguments: --apply`, Exit 2.
The activation comes before the user units and the system step, so a wrong
sudo password never keeps the commit hook from being active; the user units
come before the system step, which is the one that asks for sudo:

1. **mise.** Die Release-Binärdatei `mise-v<MISE_VERSION>-linux-x64` von GitHub, mit `MISE_VERSION` und
   `MISE_SHA256` aus `src/hal/workstation/setup.py` (ein Bump sind zwei Zeilen). Sie wird in eine
   private Staging-Datei (Modus 600) neben dem Ziel geladen; erst wenn deren sha256 dem Pin gleicht,
   wird sie 755 und per `os.replace` nach `~/.local/bin/mise` gelegt. Jeder Fehler (Timeout,
   abgeschnittener Download, falscher Hash, Schreib- oder Umbenennfehler) entfernt die Staging-Datei
   und lässt ein vorhandenes `mise` unberührt. Der Schritt läuft auch, wenn die Datei fehlt, nicht
   ausführbar ist oder einen anderen sha256 hat; ohne mise läuft `quality hygiene` nicht.
2. **quality.** `uv tool install --force` mit `QUALITY_SOURCE` aus
   `src/hal/workstation/setup.py`, dem Commit-SHA eines Tags von overnightworks/quality
   (eine neue Version ist eine Zeile). Der Schritt
   läuft auch, wenn `~/.local/bin/quality` fehlt oder nicht ausführbar ist.
3. **Engines.** `quality engines install` nach
   `~/.local/share/quality/engines`, wenn `quality engines verify` es verlangt;
   danach gilt der Schritt erst, wenn `verify` besteht.
4. **Hook-Dateien.** `pre-commit` und `pre-merge-commit` in
   `~/.local/share/home/git-hooks/`, atomar geschrieben, Modus 755. Ein
   Inhalt, der abweicht, ein verlorenes Ausführungsrecht oder ein anderer Modus als 755 wird
   repariert.
5. **Aktivierung.** `git config --global core.hooksPath` auf dieses
   Verzeichnis. It comes after the four steps above, so a failure in one of
   them never activates a hook whose scanner is missing.
6. **User units.** The jobs declared in `src/hal/workstation/jobs.py` (the backup, the
   restore test, `hal check` and `hal alarm`) are written as a `.service` and a `.timer` file each into
   `~/.config/systemd/user/`, led by a marker line that says `hal setup` rewrites the file
   and that changes belong in a drop-in (`<unit>.d/*.conf`, which `hal setup` never
   touches). The `ExecStart` runs `.venv/bin/hal` of the live checkout, `~/srv/hal`
   (`Layout.live_checkout`), whichever checkout runs `hal setup`. systemd reloads once
   after a change (also when only a unit file changed), and each timer is enabled and
   started. A file is replaced by rename, so a unit name never lacks a unit and a loaded
   timer stays active. The step replaces only a regular file whose first line is the
   marker, and the links into the live checkout's `systemd/` with the three
   `timers.target.wants/` links of the timers, which it repoints at the written files
   whatever the timers' state; no current `hal setup` writes such links. Every other entry of a
   unit's name (a file without the marker, a link elsewhere, a mask to `/dev/null`, a
   dependency link in a `*.wants/` or `*.requires/` directory) is refused before
   anything changes: `<entry> was not written by hal · move or delete it, then rerun`,
   and the row ends `nothing changed`. A failure after that check (a write, a rename, a
   `systemctl` call, a timer that is not active after enabling) ends `units may be
   partial`; a rerun classifies what is there and finishes. A changed `timers` row says
   `N timers` (every declared timer) and ` · systemd reloaded` when a reload ran; an
   unchanged row stays bare, and the plan of the first run after the move says
   `replaces 6 links with 3 timers`. The step is verified when every unit is written
   as declared, nothing needs a reload, every timer is enabled and active, and no
   link into `systemd/` is left.
7. **Ansible.** `uv tool install --force` with `ANSIBLE_SOURCE` from
   `src/hal/workstation/setup.py`, a pinned `ansible-core`; like quality, it runs
   again when `~/.local/bin/ansible-playbook` is missing or uv recorded
   another version.
8. **System.** The playbook `src/hal/workstation/system/playbook.yml` installs
   edge's files from `~/srv/hal/tunnel/` and the journal retention timer, see below.
   It also installs `msmtp` and `ca-certificates` for the mail of `hal check`, purges `rsyslog`
   with its six log files, and makes the journal Docker's default log driver in `/etc/docker/daemon.json`,
   restarting Docker while it does not report `journald`.
   It runs as root under one `sudo` call, which asks once; Ansible asks for nothing, and `sudo -k` follows
   the call, so `hal setup` leaves no cached sudo ticket. Ansible's stderr joins its output inside sudo; sudo's password
   prompt stays on the terminal, and the password never passes through hal. hal's own output callback `hal_events`,
   selected by the packaged `ansible.cfg`, writes one marker line per unreachable result and per failed result whose
   error is not ignored, and one with the final counts. The run succeeded when Ansible exited 0 and the counts show no
   failed or unreachable host; hal reads no recap text. When the counts name a failed or unreachable host, the message
   of the last such result is the fact of the red `system` row; every other unfinished run, a failure a rescue caught
   included, shows `Ansible did not finish · its output above says why`. Root executes the operator-writable
   `~/.local/bin/ansible-playbook` and `hal_events.py` from the operator's uv tool directory. The same account already
   controls both and the whole ansible-core tool root, so no new principal changes what root runs (#510 decision 5): the
   same trust the operator's Ansible had as the producer of root's modules until the agents get their own user.
   sudo logs its whole argv, so the play's extra vars never carry a secret. Ansible keeps its state
   in root's `~/.ansible`, never the operator's; a sudoers that keeps `HOME` would leave a root-owned `~/.ansible`, and
   `sudo rm -rf ~/.ansible` recovers it. The operator runs `hal setup` as themselves, never `sudo hal`.

**Who runs it.** `hal setup` resolves a role from the running user. Exactly the account `agent`
(`AGENT_USER` in `src/hal/workstation/system_step.py`) is the agent role: mise, quality, Engines, Hook-Dateien and
Aktivierung run, and PATH link, User units, Ansible, System and Geheimnisse are skipped (`path  skipped  the operator's step`, likewise `timers`; the agents hold no secrets), with exit 0 and no sudo. Everyone else, root
and a sudoers-only admin included, is the operator role, and a system step that cannot run still exits 3.
If the running uid has more than one passwd name and one of them is `agent`, `hal setup` does not guess: it exits 3 with a line saying so.

**The rows.** The ten steps print as five rows, in the form of
[docs/design/hal-output.html](design/hal-output.html): `commit hook` (mise, quality, Engines,
Hook-Dateien, Aktivierung), `path` (der Link `~/.local/bin/hal`; `unchanged`, solange das `bin/hal` des Live-Checkouts fehlt), `timers` (User units), `system` (Ansible, System) and `secrets`. A row's
event is its worst step's: failed or not started, then needs you, then changed, then unchanged,
then skipped. After the yes a row says `changed` or `unchanged` (`stored` or `complete` for the
secrets), `skipped` for the agent role; a dry run says `will change`, `unchanged`, `not checked`
(`needs sudo at a terminal`, or `needs Ansible, …` before the Ansible step has installed it) or, for the
secrets, `missing` with the names (`(by hand)` for an entry only a person can create, `(unknown)` for one whose
presence `stat` cannot tell). The last line is the verdict, counted over the five rows:
`✓ setup done · 1 changed, 4 unchanged · 47s`, `~ setup plan · 2 open, 3 unchanged · 3s · run hal setup`
or `✓ setup up to date · 5 unchanged · 21s`. The run time is whole seconds rounded down (`<1s` under one second, `1m05s` from
a minute, `1h02m` from an hour) and stands after the counts and before the hint; a failed run ends with the error pair and shows none. A step that fails prints its row as `failed` with its own
sentence, every later row as `not run`, and then `error: setup stopped at <row>` and `next: <command>`:
the command that failed (quality, Engines, Aktivierung, Ansible) or `hal setup`. For the
system row the error says what /etc is left as: `/etc unchanged` after a failed check, `/etc may be partial` after an Ansible apply that did not finish or whose `sudo -k` failed (the ticket may still be valid). The secrets row does not fail when the wizard leaves a secret open: it prints `! secrets  N open  a, b (by hand)` from what the disk shows after the walk, and the error says `setup stopped at secrets · N secret(s) still open`; a refused store (`~/.secrets` or a group folder that is a file, a symlink or too open, or a symlink at the secret's own place, fixed by `rm`) stops the walk at the first entry with one `✗ <entry>  not stored  <reason>` row, `error: setup stopped at secrets · nothing stored for <entry>` and the bare fix as `next:` (`next: hal setup` when the secret's file appeared while the page was open); another wizard exit ends with the wizard's own error pair; setup prints no second pair. After the yes the `system` row is preceded by `› system  needs sudo` and what the play does, right before the system's own sudo prompt (`[sudo] Passwort für <user>:` or sudo-rs's `[sudo: authenticate] Passwort:`); it is not counted in the verdict and is not printed for the agent role or in a dry run. A second
`--dry-run` changes nothing and downloads nothing. On a terminal the glyphs, the verdict and the `error:`/`next:`
labels are coloured with the 16 base colours, each stream on its own; `NO_COLOR` (non-empty), `TERM=dumb` and a pipe print the plain bytes. Der Hook ist die Vorlage `src/hal/workstation/hooks/commit-hook`
(POSIX sh). Er ruft `quality scan-staged`, führt danach den eigenen
`.git/hooks/<name>` des Repositorys aus (auch im Worktree, über
`--git-common-dir`) und scannt danach noch einmal, weil ein Repository-Hook
Dateien stagen kann. Exit `0` heißt sauber, `1` ein Geheimnis gefunden, `2` nicht
beurteilbar; jeder Wert ungleich `0` bricht den Commit ab. Fehlt `quality`,
bleibt der Commit gesperrt, bis `hal setup` es wieder einrichtet. Das
ist gewollt.

### The system step

edge ships the tunnel's files in `tunnel/`; the system step copies them, with
their placeholders filled, to:

- `/etc/systemd/system/cloudflared.service`, the clean base unit;
- `/etc/systemd/system/cloudflared.service.d/20-nonroot.conf` and
  `30-edge-global-stop.conf`, so the tunnel stays down after a reboot while
  `~/.local/state/edge/global-stop` exists;
- `/etc/polkit-1/rules.d/10-edge-cloudflared-stop.rules`, so you may *stop*
  `cloudflared.service` without a password, and only stop.

All four are root-owned, mode 644. `@HOME@` and `@OPERATOR_USER@` are your
home and your user; `@TUNNEL_ID@` is `tunnel:` in `/etc/cloudflared/config.yml`,
and without it the step fails before writing anything. Once the new base unit
is in place, `10-root-binary.conf` is deleted. Every run of `hal setup` reloads systemd; `--dry-run` does not.
An extra reload at the end follows only when an edge file or the retired drop-in changed;
cloudflared is never started, stopped or restarted.
Whatever is replaced or deleted of these files is copied first to
`/var/backups/home-setup/<UTC time>/`, outside `/etc/systemd/system`. The retention units
below and rsyslog's conffiles are home's own and are not backed up. `/etc/docker/daemon.json` is backed up there too, when it changes.

- **Journal retention.** The same run writes `hal-journal-retention.service` and
  `hal-journal-retention.timer` to `/etc/systemd/system` (root, mode 644), enables
  and starts the timer, and reloads systemd on every run, so an interrupted run
  converges on the next. The timer is `OnCalendar=daily` with `Persistent=true`;
  the service runs `journalctl --rotate --vacuum-time=28d`. Nothing restarts
  journald. `LOG_RETENTION_DAYS` (30) in `src/hal/workstation/system_step.py` is the
  one owner of the value; 28 is two days less, one for the span of a journal
  file and one of slack.
  - **The bound.** While the PC runs, no journal line is older than 29 days,
    1 hour and 1 minute (the autumn clock change makes one gap 25 hours, and the
    timer's default accuracy is one minute). After an
    outage, `Persistent=true` runs the missed deletion within a minute of
    boot; the lines that came due meanwhile are gone then, which is the ruled
    promise („ok a“, 22.10.2026). Nothing promises a minimum age: the journal's
    own size limits can delete younger lines.
  - **The first run** deletes every journal file older than 28 days.
  - **Rollback.** Reverting the change removes the units from the playbook but
    deletes nothing: the timer keeps running with 28 days. To retire it, make a
    reviewed change to the playbook, in this order: a `systemd_service` task with
    `enabled: false` and `state: stopped` for the timer; an `ansible.builtin.file`
    task with `state: absent` for each of the two units; a reload. Then
    `hal setup` stops the timer, deletes both units and reloads. Deleted
    journal lines do not come back.
- **rsyslog is removed.** After the refusals below pass, the play purges the package `rsyslog` (apt, no autoremove) and then
  deletes `syslog`, `auth.log`, `kern.log`, `mail.log`, `mail.err` and `ufw.log` with every rotation (`name` and `name.*`
  directly under `/var/log`, files only) **without a copy**, not even to `/var/backups/home-setup`: a copy would outlive the
  30 days. `RSYSLOG_FILE_NAMES` in `src/hal/workstation/system_step.py` is the one owner of the six names; `hal check` reads the
  same list. The purge comes first, so a running rsyslog cannot recreate a deleted file. Both tasks work by state, so a run
  interrupted between them is finished by the next `hal setup`, and a second one reports `changed=0`. The dry run lists the
  purge and each file it would delete, and changes nothing. `cloud-init.log`, `dpkg.log` and `alternatives.log` stay.
  journald is not changed: it keeps forwarding to a syslog socket nobody listens on, which is harmless.
  - **Where the lines went.** The journal holds the same lines (journald forwards, it does not move them), minus what the
    retention timer already deleted. `auth.log` held the facilities `auth` and `authpriv` (sudo, polkit, logind, cron):
    `journalctl SYSLOG_FACILITY=4 SYSLOG_FACILITY=10`. `mail.log` and `mail.err` held the facility `mail`:
    `journalctl SYSLOG_FACILITY=2`. `kern.log` held the kernel: `journalctl -k -b all`. Narrow any of them with `--since` or
    `-t <identifier>`, for example `journalctl -t sshd --since yesterday`.
  - **Rollback.** Revert the change, or the next `hal setup` purges again; then `sudo apt install rsyslog`. The deleted files do
    not come back. A purge discards a conffile of rsyslog that was modified, and the playbook never copies one first (the
    backup covers edge's files only): `dpkg --verify rsyslog` before the apply names each such file, and a reinstall brings
    back the packaged one.
- **The mail packages.** After the refusals below pass, the play installs `msmtp` and `ca-certificates` with apt, without
  Recommends, so `msmtp-mta` (which would replace the system mailer) stays out; a second `hal setup` reports `changed=0`.
  Postfix is not touched. **Rollback.** `sudo apt-get remove msmtp`; `hal check` then reports "mail failed: msmtp could not deliver via" while
  `~/.secrets/smtp/account.toml` exists.
- **The agents' account.** The play creates `agent` and nothing runs as it yet. It has its own group only, a
  locked password, the shell `/usr/sbin/nologin`, a home with mode 0700, no subuid or subgid range
  (`groupadd --gid N agent`, then `useradd --uid N --gid N -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0`, with N the lowest
  id from 1000 up that no user, group or subordinate id entry has, checked after creation), no linger, and a line in
  `/etc/cron.deny`: an existing one keeps its owner, mode and entries, a new one is `root:root 0644`, and every
  other user keeps today's cron. An `agent` that already exists with an extra group, a subuid or subgid entry
  (by name or by its uid), another shell, a usable password, linger, a home other than `/home/agent`, or a
  home that is a link or not a directory owned by it, a uid another user shares, a gid another group shares or
  a primary group other than the group `agent`, or ids that are not one uid and gid from 1000 up, is refused before
  anything is written, in the dry run too; so is a group `agent` without the account (`sudo groupdel agent` removes it;
  a failed `useradd` removes the group it just made), a new account's home path that is taken, and an
  `agent` listed in `/etc/cron.allow`. A `cron.allow` without it denies it already, and `cron.deny` stays as it is.
  The proof checks these file states; that `crontab` itself refuses the agent is not proven, the proof image has no cron.
  A revert keeps the user and its home.
- **sudo.** `hal setup` asks no sudo before its yes. After the yes, at a terminal, the run asks once for the sudo
  password, at the system's own prompt. `hal setup --dry-run` at a terminal asks once too, for Ansible's `--check --diff`.
  Without a terminal, `--dry-run` says `! system  not checked  needs sudo at a terminal`, and `hal setup` ends after its plan
  with `error: setup asks yes at a terminal · nothing changed`, `next: hal setup in your own terminal window` and exit 4, before any step;
  neither waits for a prompt.
- **Rollback.** Restore the previous `cloudflared.service`,
  `10-root-binary.conf` and `20-nonroot.conf` from the backup (their content
  before the first run is in the inventory of #9). Restore
  `30-edge-global-stop.conf` from the backup too, or remove it when the backup
  has none, because the step created it; until then the global-stop condition
  stays in force. Then run `sudo systemctl daemon-reload`, and remove
  `/etc/polkit-1/rules.d/10-edge-cloudflared-stop.rules`.
- **A failed `hal setup`.** Files are copied in the order above, so some may already be in place, and
  `10-root-binary.conf` is deleted only after all four are. The `daemon-reload` handler does not run
  after a failure, so systemd may still run its old configuration. Two cases:
  - A failure while copying leaves some files in place and `10-root-binary.conf` still there. Run
    `hal setup` again: it copies the rest, deletes the drop-in and reloads systemd.
  - A failure in the reload itself leaves every file in place, `10-root-binary.conf` already deleted
    and systemd not reloaded. Run `hal setup` again: it reloads systemd on every run,
    whatever else it finds to change.

  Or roll back as described.
- **Docker's log default.** The same run merges `"log-driver": "journald"` into `/etc/docker/daemon.json` (`DOCKER_LOG_DRIVER`
  in `src/hal/workstation/system_step.py`, which `hal check` reads too). Every other key stays, such as `runtimes.nvidia`; the file is
  written root-owned, mode 644, with sorted keys, so the diff of a file that only holds the runtime is one new line, and it is
  checked with `dockerd --validate` before it replaces the old one. A file that does not parse, one that is not an object, a
  `log-opts` key, another `log-driver`, and a Docker that does not answer `docker info` are refused before anything is
  written, edge's files included; the dry run shows the diff and the restart as changes and writes nothing.
  Docker restarts whenever `docker info` does not say `journald`, never while it does, so a run interrupted after the write
  restarts on the next. `live-restore` is off: every container stops with Docker, and one with `unless-stopped` or `always`
  starts again, one without a restart policy or stopped by hand stays down; the apps are unreachable meanwhile and running work
  is cut. `hal setup` does not wait for it, so run `hal setup` at a quiet time. Existing containers keep `json-file` until they are recreated.
  **Rescue.** When the restart fails or Docker does not report `journald`, the run writes `daemon.json` back without `log-driver`
  (`{}` when nothing else remains; the same JSON as before the run, unless the file already carried `journald`), clears the
  unit's start limit with `systemctl reset-failed docker`, restarts Docker again and fails, saying so. No backup is read and
  nothing is deleted. **Rollback.** Revert the change, land a reviewed playbook change that removes `log-driver` and restarts
  Docker, and run `hal setup`; a plain revert removes nothing. **Residual risks:** Docker stays down, and every app
  with it, when the rescue's restart fails too; and a run interrupted between the write and the rescue with Docker down
  (a hanging restart skips the rescue on Ctrl-C) makes the next apply refuse, because Docker does not answer. Then remove
  `log-driver` from `/etc/docker/daemon.json` by hand; the backup holds the old bytes.
- **Proof.** `flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 scripts/system-proof/run.sh <edge checkout> <evidence dir> <part>`, once per part, each into its own evidence dir (`<evidence dir>/fresh`, `<evidence dir>/prepared`, `<evidence dir>/shapes`, since each run truncates `cells.txt`), drives
  the step in a throwaway systemd container, never on this PC. `fresh` is the first install with both reboots, `prepared` the
  second install under both sudos, and `shapes` a third one that converges once and then refuses the foreign account shapes (A1-3);
  each part is one container, and a part that nears the lock's 1800 s cap is cut, not given more time; the measured times per part are in the header of `scripts/system-proof/run.sh`. Its cells D1-D8 also drive the mail of `hal check` there:
  the real `msmtp` against a throwaway SMTP sink and a test CA, with STARTTLS, implicit TLS, no TLS, an untrusted certificate,
  a rejected login and a stalled server. Its cells R0-R7 drive rsyslog's removal there: the image carries rsyslog, an
  unconfigured postfix and kerneloops like the PC, the six files with archives are planted before the first refused run, and
  the cells prove that a refused run and the dry run delete nothing, that the purge and the deletion are complete without
  touching the installer's logs, that mail lines stay in the journal, that a retry converges, that kerneloops restarts without
  `kern.log`, and that `apt install rsyslog` restores a working package. The image is Ubuntu 26.04, the PC's release, so the proof
  runs that release's removal scripts, but with systemd as PID 1 of a container, not the PC's boot; the PC's own facts cover that.
  The container runs a real Docker engine (its images and snapshots live in anonymous volumes that `run.sh` removes with the container);
  cell DK1 proves, before the first apply, that it answers with the default `json-file` log driver, runs an imported rootfs
  offline and starts without `/etc/docker/daemon.json`. DK2 proves the merge (no file, and the PC's 128-byte file with its
  backup), DK3 the refusals and a Docker that does not answer, DK4 the dry run and the restart on need only, DK5 that a
  running `unless-stopped` container comes back, one stopped by hand stays down and both keep `json-file`, DK6 that a
  container created afterwards is read by `docker logs`, `docker compose logs` and `journalctl CONTAINER_NAME=`, and DK7 the
  rescue, against a proof-only `docker.service` drop-in whose flag contradicts the file. The proof runs the same 26.04 Docker
  package as the PC, but inside a container and without a GPU. The agents' refusal cells A1-8 and A1-9 run against the engine's own `docker.socket`.

### Das Mail-Konto von `hal check`

Zwei Dateien, beide von Hand angelegt, beide Modus 0600, beide im Geheimnis-Manifest:

- `~/.secrets/smtp/account.toml` mit genau den Schlüsseln `host`, `port`, `user` (zugleich Absender) und `to`; nie das
  Passwort.
- `~/.secrets/smtp/password`: ein App-Passwort nur dafür, sonst nichts.

`msmtp` läuft als du und liest das Passwort beim Senden selbst (`--passwordeval`); `hal` öffnet die Datei nie, und das
Passwort steht in keinem Terminal, Log, keiner Mail, keinem Argument und keiner Zustandsdatei. Rotieren heißt die Datei
ersetzen (neues App-Passwort anlegen, das alte widerrufen); die Kopie in songmakers `.env` ziehst du von Hand nach, bis
songmaker die Datei selbst liest. Akzeptiertes Risiko: Jeder Prozess, der als du läuft, Agenten eingeschlossen, kann über
dieses Konto senden; darum ein App-Passwort nur dafür, widerrufbar.

Die Mail geht nur über TLS (STARTTLS auf 587, implizites TLS auf 465), das Serverzertifikat wird gegen den System-Trust-Store
geprüft; ein Server ohne TLS oder mit unbekanntem Zertifikat bekommt weder Mail noch Passwort. Nichts schaltet das ab: keine
Konfigurationsdatei, kein Schalter.

### Was der Hook nicht garantiert

Die Zusage ist enger als „jeder Commit“:

- Nicht erfasst: `--no-verify` bei `git commit` und `git merge`; Commits aus
  rebase, cherry-pick, revert und `git am`; Plumbing wie `git commit-tree`; ein
  einzelner Befehl mit `-c core.hooksPath=…` oder `GIT_CONFIG_*` (songmakers
  Deploy-Skript tut das absichtlich); ein anderer OS-Benutzer oder ein anderes
  HOME.
- Rückhalt: die Agentenregel „nie `--no-verify`“ (`AGENTS.md`), Push Protection
  auf den öffentlichen Repositories und das CI-History-Gate dort, wo es
  eingeführt ist.
- Eine Allowance im selben Commit gilt. Kontrolle ist das Review dieses Diffs:
  ein Allow-Eintrag steht dort als sichtbare Zeile mit Hash und Grund.
- Der Framework-Hook von hopin (`.pre-commit-config.yaml`) läuft hier nicht mit.

## hal alarm

`hal alarm` ist der Fünf-Minuten-Lauf: Er fährt nur die Prüfungen `platform` (Dienste, Jobs, Neustart, Platte) und
`backup` des täglichen `hal check` mit denselben Regeln und merkt sich je Fund, in wie vielen Läufen hintereinander er
auftrat. Ein Fund zählt erst, wenn er in `runs` Läufen hintereinander auftrat (Default 2); ein Fund, der einmal fehlt,
beginnt von vorn. Was zählt, geht in dieselbe gemerkte Fundmenge wie beim täglichen Lauf
(`~/.local/state/hal/check-findings.txt`); die Zahl der Läufe steht daneben in `alarm-streaks.json`. Mail, Popup, Wortlaut und
Kanalregeln sind die des täglichen `hal check` (siehe oben): eine Mail, wenn ein Handlungsbedarf zählt, eine, wenn er weg
ist, und der 09:00-Lauf meldet nichts davon noch einmal, so wenig wie der Alarm, was der tägliche Lauf schon gemeldet
hat. Ein Alarmlauf, der scheitert, ist ein `job-failed` (`hal-alarm.service`). Der Lauf endet mit Exit-Code `0`, bei
ungültiger Konfiguration mit `2`.

## Konfiguration

`hal` liest seine Einstellungen aus `~/.config/hal/config.toml`, eine Tabelle je
Timer-Job mit Einstellungen; `hal` schreibt, verschiebt und löscht die Datei nie.
Ohne die Datei gelten die Defaults. Eine unbekannte Tabelle, ein unbekannter
Schlüssel, ein falscher Werttyp, Inhalt, der kein TOML ist, oder eine nicht
lesbare Datei ist ein Konfigurationsfehler: `hal check` meldet ihn auf stderr
und beendet sich mit Exit-Code 2, statt mit falschen Einstellungen
weiterzulaufen. Die Datei enthält kein Geheimnis; das SMTP-Konto bleibt unter
`~/.secrets/smtp/`.

### `[check]`

| Schlüssel | Default | Bedeutung |
|---|---|---|
| `notify` | `true` | `false` schaltet Benachrichtigung und Mail von `hal check` und `hal alarm` ab |

### `[alarm]`

| Schlüssel | Default | Bedeutung |
|---|---|---|
| `interval` | `5` | Minuten zwischen zwei Läufen von `hal alarm`; `hal setup` schreibt `hal-alarm.timer` daraus (`OnUnitActiveSec`) |
| `runs` | `2` | Läufe hintereinander, in denen ein Fund auftreten muss, bevor er zählt |

Beide Werte sind ganze Zahlen ab 1. Ein neuer `interval` gilt nach `hal setup`; `runs` gilt beim nächsten Lauf.

Beispiel:

```toml
[check]
notify = true

[alarm]
interval = 5
runs = 2
```

## Installation

```
cd ~/srv/hal
uv sync --locked
bin/hal setup
```

Der Schritt „User units“ von `hal setup` (siehe [hal setup](#hal-setup)) schreibt die Units aus
der Job-Liste `src/hal/workstation/jobs.py` und startet die Timer, darunter `hal-check.timer`.

`uv sync --locked` baut die `.venv` des Checkouts. `bin/hal` ist der Starter,
der `.venv/bin/hal` des Checkouts ausführt; der Link
unter `~/.local/bin` heißt `hal`, damit `hal` ihn findet; den Link legt der Schritt `path` von `hal setup` an
und zieht ihn nach, wenn der Checkout umzieht. Die erzeugten systemd-Units rufen
`~/srv/hal/.venv/bin/hal` direkt auf und hängen so an keinem Link. `hal`
läuft mit dem Python der `.venv` (`requires-python >= 3.14`). Das
Paket ist editierbar installiert: eine Änderung unter `src/` wirkt ohne
Neuinstallation. `hal update` synct die Abhängigkeiten nach jedem Update selbst; `uv sync --locked`
braucht es nur für diese Installation und nach dem Pull, der eine Revision repariert, auf der hal
nicht startet ([stack.md](stack.md), „Den Checkout aktualisieren“); `hal` über `bin/hal` aufzurufen
synct ebenfalls, bevor der Timer läuft.

`hal-check.timer` läuft täglich 09:00 (`Persistent=true` holt einen verpassten Lauf
nach) und fährt nur `hal check`; `hal-alarm.timer` fährt `hal alarm` alle `[alarm] interval` Minuten
(Default 5, ab dem Start und nach jedem Lauf).

## Tests

```
uv run pytest          # nur die Tests
uv run pytest --cov    # zusätzlich die 100-%-Grenze aus pyproject.toml
uv run ruff check .
```

`src/hal/workstation/` hält 100 %
Zeilen- und Branch-Abdeckung; `fail_under = 100` in `pyproject.toml` lässt
jeden Coverage-Lauf rot werden, der darunter bleibt. Die Layout-Prüfung des
Wurzelverzeichnisses gehört der Qualitätsschranke (`quality / verdict`); was dort liegt und nicht auf
ihrer Basisliste steht, deklariert `quality/config.toml` mit Grund.
`.github/workflows/ci.yml` fährt alles bei jedem Push und Pull Request.
