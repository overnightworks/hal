# Externe Dienste als Code

Referenz fuer den Betreiber und fuer Entwickler von `external/` und `src/hal/stack/external/`. Sie nennt die
Befehle und was sie garantieren; `hal apply --help` und der Code halten den Rest. Wo diese Schicht in
der Plattform liegt: [architecture.md](architecture.md). Der lokale Teil von `hal apply` und die
Publish-Phase: [stack.md](stack.md).

Cloudflare wird mit OpenTofu als Code verwaltet (`external/`; GitHub folgt mit edge#30 X2/X3). Der State
liegt nie im Checkout, sondern verschluesselt in `~/.secrets/opentofu/fleet.tfstate`.

## Die Umgebung von tofu

Die Publish-Phase von `hal apply` verweigert ein `tofu`, dessen Version nicht dem Pin in
`external/main.tf` entspricht. Sie liest Token-Dateien (erwartet wird je 0600, geprueft wird das hier
nicht) und gibt sie nur an das Kind `tofu` weiter, dessen Umgebung eine Allowlist ist (kein `TF_LOG*`,
`TF_CLI_ARGS*`, `TF_ENCRYPTION`, `GITHUB_*`, `GH_*`, Proxy aus der Shell):

| Datei | Variable im Kind |
|---|---|
| `~/.secrets/cloudflare/fleet-read` | `CLOUDFLARE_API_TOKEN` |
| `~/.secrets/cloudflare/fleet-write` | `CLOUDFLARE_API_TOKEN` (statt der Lese-Datei, sobald geschrieben wird) |
| `~/.secrets/opentofu/state-passphrase` | `TF_VAR_state_passphrase` |

Die weiteren Token-Dateien folgen mit X5b (home-tools#10).

## `hal check hosts [--json]`

Liest nur `~/.secrets/cloudflare/fleet-read` und sendet es im `Authorization`-Header an
`api.cloudflare.com`: kein `tofu`, kein GitHub-Token, keine State-Passphrase, kein Schreib-Token, kein
Terminal, keine Abfrage. Das Token steht in keiner URL, keiner Ausgabe und keinem Fehlertext;
Weiterleitungen und der Proxy aus der Shell werden nicht befolgt.

Es liest Zone, DNS-Records, Access-Apps, Access-Gruppen und den Tunnel und vergleicht sie mit den Hosts
aus `fleet.yaml` des laufenden Checkouts: fehlende oder falsche Records und Apps, falsche Policies,
unerwartete Apps an oeffentlichen Hosts sowie Records und Apps, die niemand deklariert hat (`hal apply`
loescht sie nie; die Publish-Phase endet auf demselben Check). Ohne Access auf dem Konto ist das nur dann ein Befund,
wenn ein Host `bypass` oder `protected` ist; widerspricht sich die Abfrage ("Access aus" erst nach den
Apps), ist es Exit 3. Exit 0 keine Befunde, 1 Befunde, 3 nicht pruefbar, 130 unterbrochen (nur vor der
Ausgabe). Mit `--json` ist stdout genau ein Objekt `{"hosts": [{problem, subject, detail, next}]}`
(bei Exit 3 leer, die Ursache als `error: hal check: hosts: cannot check, …` auf stderr). `hal check
hosts` liest Cloudflare; `hal check exposure` bleibt lokal, und `--allow-list` gehoert nur zu
`exposure`; ein nacktes `hal check` ist die taegliche Pruefung (`docs/home.md`). Der Abschluss der Publish-Phase sieht weiter Exit 2 fuer "nicht pruefbar".

Zusaetzlich fragt der Check jeden deklarierten Host mit Record einmal mit `GET /` ueber HTTPS, ohne
Anmeldedaten, Cookies und Weiterleitungen (10 s je blockierender Operation; die Wildcard unter
`edge-host-check.<zone>`, nur solange Access an ist; der Name ist im Katalog reserviert).
`answer-wrong`: die Antwort hat kein `cf-ray`, ein oeffentlicher oder `bypass`-Host leitet auf Access
um, oder die geschuetzte Wildcard leitet nicht auf Access um (oder ist eine Challenge). `unreachable`:
die Anfrage scheiterte. Eine Challenge auf einem oeffentlichen oder `bypass`-Host besteht, ein 5xx mit
`cf-ray` auch: ob der Dienst lebt, sagt `ready`. Als Access-Umleitung zaehlt nur Cloudflares kanonische
Access-URL. Kein Befund zitiert Header, Ziel oder Fehlertext.

## Die Publish-Phase von `hal apply`

Schreibt die Aenderungen auf die Live-Dienste, mit `~/.secrets/cloudflare/fleet-write` (dieselbe
Allowlist-Umgebung, dieselbe State-Passphrase).

- **Wo und wie.** Nur aus `~/srv/hal` als Haupt-Worktree auf einem sauberen `main` (sonst Exit 2 mit
  dem Grund) und nur an einem Terminal (stdin und stdout; sonst Exit 1 vor `tofu`). Es plant in eine
  Datei, zeigt den Plan und wendet genau diese Datei erst nach der Eingabe `yes` an (alles andere:
  Abbruch, Exit 1). Ein Plan ohne Aenderungen endet mit Exit 0 ohne Frage. Das schuetzt gegen
  versehentliche und nicht-interaktive Laeufe (CI, Skript, `-auto-approve`); es ist keine
  Identitaetspruefung: ein Agent kann ein pty oeffnen und `yes` tippen, erst D14 macht daraus "nur der
  Betreiber".
- **`ready`-Schutz.** Hat der Plan Aenderungen, fragt `apply` vor dem `yes` jeden aktivierten Host mit
  `ready` (`fleet.yaml`) nach diesem Pfad auf seinem `target` (`GET`, `Host` = FQDN, kein Redirect,
  10 s, kein Retry); nur 2xx zaehlt. Antwortet einer nicht, endet es mit Exit 1 vor dem `yes`: jeder
  nicht antwortende Host steht mit Pfad, Ziel und Status auf stderr, `tofu apply` laeuft nie, die
  Plan-Datei wird geloescht. Das gilt auch fuer eine ganz andere Aenderung (Host gestoppt, abgestuerzt,
  startet noch); `enabled: false` nimmt den Host aus der Pruefung.
- **Der Plan als Zeilen.** `tofu plan -json` liefert nur Diagnosen: ein Plan ohne Aenderung und ohne
  Diagnose ist die eine Zeile `cloudflare  current  nothing to publish`, jede Warnung eine `!`-Zeile
  (`warning`), jeder Fehler eines gescheiterten Plans eine `✗`-Zeile (`not planned`), je mit tofus
  Zusammenfassung und darunter gedimmt der Erklaerung. Mit Aenderungen zeigt `tofu show -no-color`
  genau die geschriebene Plan-Datei, vor Bereitschaftspruefung und `yes`; scheitert das `show`, endet
  es wie ein gescheiterter Plan (Exit 2, nichts angewendet). Jeder Text ist von Token und Passphrase
  bereinigt und maskiert; `tofu show -json` bleibt aus, es traegt jeden sensitiven Wert im Klartext.
- **Die Plan-Datei** liegt verschluesselt (X1a) in `~/.secrets/opentofu/plans/` (0700) und wird nach
  Erfolg, Abbruch, Fehler und SIGINT/SIGTERM geloescht. Eine nach SIGKILL uebrig gebliebene loescht und
  nennt der naechste Aufruf (`check` raeumt nicht auf).
- **Unterbrechung.** Strg-C oder SIGTERM geht genau einmal als SIGINT an `tofu`; der Wrapper wartet, bis
  `tofu` sauber beendet ist, weitere Strg-C werden ignoriert, und die Meldung verweist auf
  `hal check hosts`. Die Pruefung laeuft dann nicht von selbst: nichts Ungeprueftes wird
  behauptet.
- **Der Host-Check am Ende.** Jeder `apply`, der etwas geaendert haben kann oder nichts zu tun fand,
  endet auf demselben Check wie `hal check hosts` (ohne `--json`; er liest `fleet-read`, das `apply` vor
  dem Plan prueft: fehlt es oder ist es leer, Exit 2 ohne `tofu`; das Schreib-Token erreicht den Check
  nie). Er vergleicht den tatsaechlichen Zustand mit der Deklaration, nicht mit dem Plan: ein geplanter
  Fix entschuldigt nichts, und ein undeklarierter Record laesst auch einen sonst fertigen `apply` mit
  Exit 1 enden.
- **Exit.** 0 angewendet (oder nichts zu tun) und der Check meldet nichts; 1 verweigert, abgebrochen,
  fehlgeschlagen oder der Host-Check meldet etwas oder laeuft nicht; 2 nicht planbar (nie nach einem
  Apply).

## Was `apply` ausserdem setzt

**Welcher Tunnel.** `hal apply` und `hal check hosts` suchen hals Tunnel ueber die ID in
`/etc/cloudflared/config.yml`, die Datei, die der laufende Tunnel liest; weitere Tunnel im Konto
spielen keine Rolle, ausser ein Host nennt einen davon (unten). Fehlt die Datei oder nennt sie
keine ID, oder hat kein lebender Tunnel die ID, endet der Lauf mit einem Fehler.

**Ein Host auf einem anderen Tunnel.** Ein Host im Katalog kann mit `tunnel: <name>` einen anderen
Tunnel im Konto der Zone nennen (ein kleingeschriebenes DNS-Label; nicht neben `target`, nicht auf
`*`). `apply` sucht jeden genannten Tunnel einmal ueber seinen Namen unter den lebenden Tunneln und
richtet den Record des Hosts auf ihn; der Host verliert nur seine Zeile in hals Tunnel, die der
Besitzer des anderen Tunnels in dessen Ingress schreibt. Record, `deny_public`, Access und der
Import bleiben bei hal, wie ohne den Schluessel. Nennt der Name hals eigenen Tunnel, scheitert der
Plan.
- **Umziehen:** erst meldet der Besitzer des Tunnels den Host dort bereit, dann bekommt der Host im
  Katalog `tunnel: <name>`, dann `hal apply`. Die `ready`-Pruefung der Publish-Phase fragt ihn
  nicht mehr: seine Bereitschaft belegt der Besitzer des Tunnels vor dem Umzug, danach belegen sie
  `/health` mit 200 und die abgewiesenen `deny_public`-Pfade unter dem oeffentlichen Namen.
  `ready` bleibt im Katalog Pflicht fuer den Host einer App.
- **Zurueck** gilt fuer den Host einer App oder Einheit, die hal betreibt: die Zeile `tunnel:`
  entfernen, `hal apply`; Record und Tunnel-Zeile kehren zu hals Tunnel zurueck. Ihr Container
  muss vor diesem `hal apply` laufen und gesund sein, denn die Publish-Phase prueft `ready` ueber
  hals Traefik und verweigert den Lauf sonst. Wurde er gestoppt, kommt `hal start <app>` zuerst.
- **Ein Host ohne `repo` und `run`** (heute `skat` und `hopin`): hal betreibt nichts dahinter. Der Besitzer des
  Tunnels bedient ihn und stoppt oder startet ihn; hal haelt nur Record, `deny_public` und Access.
  Der Rueckweg ist seiner, und `hal stop` und `hal start` kennen den Host nicht.
- **Gibt es den genannten Tunnel nicht mehr** (geloescht, umbenannt oder doppelt), scheitert jeder
  `hal apply` und jeder `hal check hosts`, bis der Host zurueckgezogen ist; ein Tunnel, der
  geloescht werden soll, verliert deshalb zuerst seine Hosts im Katalog.
- **`hal check hosts`** erwartet den Record eines solchen Hosts als CNAME auf dessen Tunnel; zeigt
  er auf hals Tunnel (oder der eines eigenen Hosts auf den anderen), meldet er `record-wrong`.
- **`hal stop <dienst>`** (eine Einheit oder App, die hal betreibt) setzt seine Sperre weiter in hals Traefik; die Zeile nennt jeden Host,
  den sie nicht schliesst (`<fqdn> stays served by tunnel <name>`). `hal stop --all` schliesst nur
  hals Tunnel.

**Die Tunnel-Zeilen.** Eine je Host aus dem Katalog, der auf hals Tunnel liegt, die 404-Regel
zuletzt. Die Konfiguration des Tunnels gehoert ganz dem Katalog: eine Zeile von anderswo zeigt `plan` als entfernt, und sie
verschwindet nach `yes` (anders als undeklarierte Records und Apps). Das gilt, **solange Cloudflare den
Tunnel verwaltet (`config_src = cloudflare`)**. Solange er `local` ist, bedient cloudflared
`/etc/cloudflared/config.yml`, und die Zeilen, die `apply` schreibt, bedienen nichts. Der Wechsel von
`local` auf `cloudflare` ist einseitig (laut cloudflared-Maintainern), macht der Betreiber
(overnightworks/edge#168), und `apply` loest ihn nicht aus.

**HSTS der Zone** (`cloudflare_zone_setting.hsts`, `security_header`): `max-age=31536000;
includeSubDomains; preload`, auf dem Apex und jeder Subdomain. Die Einstellung allein veroeffentlicht
nichts; die Preload-Liste der Browser kennt die Domain erst nach dem Absenden des Formulars (nicht
umkehrbar fuer Monate). Reihenfolge:

0. Der Betreiber gibt im Cloudflare-Dashboard beiden Tokens das Recht (`fleet-read`:
   `Zone › Zone Settings › Read`; `fleet-write`: `Zone › Zone Settings › Edit`), vor `hal apply`. Der
   Wert des Tokens bleibt dabei erhalten, an den Dateien aendert sich nichts.
1. `hal apply`; die Publish-Phase wendet die Einstellung an; ein zweites `hal apply` zeigt fuer die
   Publish-Phase `cloudflare  current  nothing to publish` und fragt nichts.
2. Der Header `strict-transport-security` erscheint genau einmal auf Apex, `www` und `auth`. Sind es
   zwei, verwerfen zuerst die Ursprungsdienste ihre eigene (in den Items von webauth und Keycloak).
3. `https://hstspreload.org/api/v2/preloadable?domain=hallucinai.de` meldet keinen Fehler.
4. Der Betreiber sendet das Formular auf hstspreload.org ab.

Zuruecknehmen vor Schritt 4: `enabled = false` setzen und anwenden (den Block zu loeschen ist nicht
belegt als Zuruecksetzen bei Cloudflare). Nach dem Absenden reicht das nicht, denn die Domain bleibt auf
den Preload-Listen, bis sie entfernt ist: den Header ohne `preload` ausliefern, das Formular auf
https://hstspreload.org/removal/ absenden und bis zur Entfernung gueltiges HTTPS auf jeder Subdomain
halten; Browser, die den Header sahen, behalten ihn bis zum Ablauf seines max-age.

**Network Error Logging aus** (`cloudflare_zone_setting.nel`, `nel`): Ist es an, haengt Cloudflare an
jede Antwort der Zone `nel` und `report-to`, und der Browser des Besuchers meldet seine Netzfehler an
`a.nel.cloudflare.com`, eine Anfrage an Dritte, die keine unserer Seiten verlangt hat. Die Einstellung
schaltet es fuer die ganze Zone ab; nach `hal apply` tragen Antworten von Apex, `www`, `auth` und
songmaker weder `nel` noch `report-to` noch `reporting-endpoints`.
Browser, die Cloudflares NEL-Richtlinie schon halten, melden weiter, bis ihr `max_age` ablaeuft: eine
Antwort ohne den Header loescht eine gemerkte Richtlinie nicht (W3C NEL, 4.2). Zuruecknehmen: `enabled =
true` setzen und anwenden; den Block zu loeschen laesst NEL aus, weil das `Delete` des Providers nichts
tut.

**Die Client-Adresse** (`cloudflare_ruleset.client_address`, Phase `http_request_late_transform`):
`Forwarded` ist die Adresse, die Cloudflare sah (`for=<IPv4>;proto=https`, bei IPv6
`for="[<IPv6>]";proto=https`); ein vom Besucher gesendetes `Forwarded` wird ueberschrieben. Keycloak
liest nur diesen Header (`KC_PROXY_HEADERS=forwarded`) und speichert in seinen Ereignissen (Anmeldungen
und fehlgeschlagene Anmeldungen, 90 Tage) deshalb die Adresse des Besuchers, nie einen gefaelschten
`X-Forwarded-For`; bei IPv6 mit den Klammern des Headers. Apps, die `X-Forwarded-For` loggen, bleiben
faelschbar; jede liest `Forwarded` oder `Cf-Connecting-IP` selbst.

**Der oeffentliche Ausschluss** (`cloudflare_ruleset.deny_public`, Phase `http_request_firewall_custom`):
Pfade aus `deny_public` eines Hosts (songmakers Host: `/auth/backchannel-logout` und `/metrics`; die Hosts von hopin, skat und presentator (`presentator`, `presentator-talk`): `/auth/backchannel-logout`) sind von
aussen nie erreichbar. Eine Block-Regel je Pfad, die alle Hosts abdeckt, die ihn auffuehren, weist
sie bei Cloudflare ab, vor dem Tunnel; der Host gilt mit und ohne `:<port>`. Cloudflare
normalisiert die URL vorher ([Doku](https://developers.cloudflare.com/rules/normalization/how-it-works/)),
laesst `%2F` aber kodiert und fuehrt Schraegstriche nur im optionalen Typ "Cloudflare" zusammen, den
die Zone nicht erzwingt. Die Regel dekodiert den Pfad deshalb selbst (`url_decode(..., "r")`) und prueft ihn
mit `wildcard` ([Operatoren](https://developers.cloudflare.com/ruleset-engine/rules-language/operators/)):
case-insensitiv und im Free-Plan verfuegbar, anders als `matches` (ab Business). Jeder `/` des Pfads
wird `/*`: abgewiesen wird jeder dekodierte Pfad mit `auth/` und spaeter `backchannel-logout`, etwa
`/auth/backchannel-logout/`, `//auth/...`, `/auth%2F...`, `/AUTH/...`, `/auth//...` und
`/oauth/backchannel-logout` (der Ausschluss schlaegt eher zu viel zu); `/metrics` trifft jeden
Pfad mit `metrics`, songmakers Routen enthalten sonst keinen. Der Free-Plan erlaubt 5
Custom-Regeln, also fuenf Pfade, nicht fuenf Hosts; songmakers Host fuehrt davon zwei auf, die Hosts von hopin, skat und presentator fuegen keinen hinzu. Der DNS-Eintrag jedes Hosts wartet auf dieses Regelwerk: ein
fehlgeschlagener Ausschluss veroeffentlicht nichts. Gibt es den Einstiegspunkt
`http_request_firewall_custom` der Zone schon (Dashboard-Regeln), schlaegt das Anlegen fehl: dann
vor dem ersten `hal apply` importieren (`cloudflare_ruleset.deny_public[0]`, ID `zones/<zone_id>/<ruleset_id>`,
[Import beim Provider 5.28.0](https://github.com/cloudflare/terraform-provider-cloudflare/blob/v5.28.0/docs/resources/ruleset.md#import)).
Der Import behaelt die vorhandenen Regeln der Zone nicht: die Regeln der Ressource kommen ganz aus dem
Katalog, der naechste Plan zeigt also jede vorhandene Dashboard-Regel als entfernt. Der Betreiber bricht
vor dem `yes` bei jeder solchen Entfernung ab: soll die Regel bleiben, schreibt er sie zuerst ueber ein
Item in den Katalog, sonst entfernt er sie bewusst. Nichts verschwindet ungesehen. Das Token-Recht
`Zone › Zone WAF` (Lesen fuer `fleet-read`, Edit fuer `fleet-write`) ist nicht gemessen: es kommt vor `hal apply` dazu, wenn ein 403 es nennt.

**Die Weiterleitung des Apex** (`cloudflare_ruleset.apex_redirect`, Phase `http_request_dynamic_redirect`):
`cloudflare.redirect` im Katalog nennt die Namen (`hallucinai.de` und `www`), das Ziel
(`https://auth.hallucinai.de/`, dessen Adresse Keycloak selbst auf die Kontokonsole leitet) und die
`serve`: die Seiten (`/impressum`, `/datenschutz`, `/nutzungsbedingungen` und `/favicon.ico`, die automatische Anfrage des Browsers, die nicht zu auth gehen darf) und das Praefix der Dateien (`/_rechtliches/`), die der Apex selbst beantwortet. Cloudflare antwortet
mit 302, ohne Tunnel: alles ausser den Seiten und dem Dateipraefix des Apex geht zum Ziel, Pfad und
Query entfallen (`preserve_query_string = false`); alte Links behalten keinen Pfad (Betreiber, 18.10.2026).
Single Redirects laufen der Reihe nach, und ein Redirect beendet die Auswertung
([Doku](https://developers.cloudflare.com/rules/url-forwarding/), dort auch die 10 Regeln des Free-Plans):
je Seite steht eine Regel vor der letzten, die jede andere Schreibweise (Grossschreibung, Schraegstrich, `www`) auf den genauen Pfad am Apex leitet; die letzte Regel nimmt die Seiten und das Dateipraefix des Apex aus, sie gehen durch den Tunnel `platform` zur Plattform, die sie beantwortet. Der Host gilt mit und ohne `:<port>`. Nur https wird weitergeleitet (`ssl`): `http://` geht zuerst auf demselben Host nach https (Always Use HTTPS), wie es der HSTS-Preload verlangt. Die Namen behalten proxied
DNS-Eintraege, haben aber keine Zeile in hals Tunnel und keinen Ausschluss; ihr Eintrag wartet auf dieses Regelwerk,
wie auf den Ausschluss. Der Apex ist der Host von `legal` mit `tunnel: platform` (oben, ein Host auf einem anderen
Tunnel): sein Record zeigt auf den Tunnel der Plattform, der Record von `www` auf hals Tunnel. Die Einheit `legal`
laeuft weiter, und `hal apply` baut weiter `legal/built/`, doch nichts Oeffentliches erreicht sie; bis zum Umstieg auf
die Plattform ist sie das Ziel des Rueckwegs: den Schluessel `tunnel` zuruecknehmen, dann `hal update` und `hal apply`. Die Felder `action_parameters.from_value` des Providers 5.28.0:
[ruleset.md](https://github.com/cloudflare/terraform-provider-cloudflare/blob/v5.28.0/docs/resources/ruleset.md).
Gibt es den Einstiegspunkt `http_request_dynamic_redirect` der Zone schon (Dashboard-Regeln), schlaegt das
Anlegen fehl: dann vor dem ersten `hal apply` importieren (`cloudflare_ruleset.apex_redirect[0]`, ID
`zones/<zone_id>/<ruleset_id>`, Import wie beim Ausschluss); der Import behaelt die vorhandenen Regeln nicht,
der naechste Plan zeigt jede als entfernt, und der Betreiber bricht vor dem `yes` ab, bis die Regel im
Katalog steht oder bewusst entfaellt. Erwartet nach dem Anwenden: `https://hallucinai.de/x?y=1` und
`https://www.hallucinai.de/` antworten 302 nach `https://auth.hallucinai.de/`; `/impressum`,
`/datenschutz` und `/nutzungsbedingungen` antworten 200 ohne `Location`, `/favicon.ico` 404 ohne `Location`. Das Token-Recht
`Zone › Single Redirect` (Lesen fuer `fleet-read`, Edit fuer `fleet-write`) ist nicht gemessen: es kommt vor `hal apply` dazu, wenn ein 403 es nennt.
