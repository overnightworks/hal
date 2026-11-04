# hal check, hal backup and hal restore

Reference for the operator. It says what the commands guarantee and what they do not; `hal check
--help`, `hal backup --help`, `hal restore --help`, `backup/apps.toml`, `src/hal/exposure/`, `src/hal/backup/` and `src/hal/workstation/jobs.py`
hold the mechanics. The data layer and the re-setup path they serve: [architecture.md](architecture.md)
(L5, section 6).

## hal check

A read-only alarm: it fails loudly when something on this PC reaches beyond loopback. Docker's loopback default is not set yet (edge#291), so a publication can bind every
interface; the daily `hal check` reports it as its exposure area.
Run `hal check exposure` (one row for each process or container, then a verdict) or `hal check exposure --json` (the same findings for
machines). It has two areas, `exposure` (local) and `hosts` (reads Cloudflare, see
docs/external.md), one per run. A bare `hal check` is not an area: it is the daily check, which also
mails and pops up what is new (docs/home.md), and takes no `--json`.

It runs `docker ps --all`, `docker inspect` and `ss -H -ltnupe` (fixed arguments, no shell, nothing
written) and reads `/proc/<pid>/cmdline` of a listener's process when it is an interpreter (python, node, nodejs, perl, ruby). It reports, by `problem`:

| Problem | When |
|---|---|
| `publication-beyond-loopback` | a container publishes a port on an address that is not loopback |
| `publication-without-host-ip` | a container publishes a port without a host IP (Docker would bind every interface; `-P` does this for every exposed port) |
| `listener-beyond-loopback` | a TCP or UDP socket listens on a non-loopback address and no allow-list entry permits it |
| `routed-without-edge-name` | a container carries `traefik.enable=true` but no `edge.name` label |
| `invalid-edge-name` | a container's `edge.name` or `edge.alias` does not match `^[a-z0-9-]{1,63}$` |
| `duplicate-edge-name` | two or more running containers claim the same host by `edge.name` or `edge.alias` (one finding names them all) |

Stopped containers count too, since their publications and labels return when they start; only the
duplicate check looks at running containers alone. docker-proxy's socket for a running container's
publication is not reported again as a listener, and `docker.service` never belongs on the allow-list.
A listener run by an interpreter is named by its script or module (`wsdd`, not `python3`); that name only names the finding and never matches an allow-list `owner`, since any process chooses its command line. An `owner` matches the process name (`python3`), or, when it names a systemd unit (`avahi-daemon.service`), only that unit under system.slice, never a process named like it, since any user can name a process. When the command line cannot be read, or is inline code, the finding names the process.
The rows name the subject, the protocol and a count, never an address, a port or the `problem` code;
`--json` lists each socket. It is one object, `{"exposure": [...]}`, whose list is deduplicated and stably ordered, with objects holding `problem`, `subject`, `protocol`,
`address`, `port` and `edge_name` (`null` where they do not apply; `port` is a string such as
`"8000-8010"` for a range).

Exit 0, printing `✓ nothing reaches beyond loopback`: every publication binds loopback and every listener is loopback or allow-listed. Exit 1: at least
one finding. Exit 3: it cannot check, with the cause as `error:` on stderr and nothing on stdout (allow-list missing or invalid, or `docker`/`ss` failed, timed out
after 30 s or printed something unreadable; `docker inspect` answering fewer containers than `docker ps`
listed is unreadable too).

### The allow-list

`src/hal/exposure/allow-list.toml` (or `hal check exposure --allow-list PATH`; a bare `hal check
--allow-list` is a usage error, since only `exposure` takes it) names the known listeners beyond loopback. The default ships in the
package, so it is found whatever the current directory. Docker publications are never
allow-listed. Each `[[allow]]` entry needs a `reason` and a `port`, an `owner` (process name, or the
system unit under `system.slice`), or both, plus `protocol` (`tcp` or `udp`); any other key is an error.
Allow by `owner` alone only when the service opens random ports.

## hal backup and hal restore

A weekly encrypted backup of the declared apps (Songmaker, Keycloak, LiteLLM and presentator) into a local restic repository,
and a monthly test that restores the last successful backup's snapshot and proves it is good.

**What it protects against:** accidental deletion and corruption. The repository `~/backups/restic` sits
on the same disk as the data, so it does **not** protect against losing the disk. A second disk or an
off-site copy is a later slice (architecture.md, gap 19).

**Platform rules for every app.**

- *Data classes.* An app's record in `backup/apps.toml` names its persistent data: the database and the audio or files volume. That is backed up and restore-tested. What the record does not name, such as caches and model weights, is rebuildable and is not backed up; no key marks it.
- *Online.* No service is stopped: a PostgreSQL app is dumped transactionally, a SQLite app is copied through SQLite's online backup, and volumes are read live. The app keeps running.
- *One app fails alone.* An app whose volume or database container is missing fails only itself; the others still back up and are forgotten, and the repository is checked. The failed app is not forgotten in that run, so a partial snapshot of it never displaces its last good one.
- *Restore goes to a new folder.* `hal restore --target` refuses a directory that exists. The only form that changes a live database is `hal restore <app> --live`: it loads a DB-only app's snapshot into its live database while the app is switched off (below).
- *0 rows is valid.* The restore test requires rows only where the record says `require_rows = true`.
- *One retention.* Every app's snapshots follow the same policy, 4 weekly and 3 monthly, and pre-apply snapshots keep their own last 10, and each forget of an app drops those older than 90 days (below). There is no per-app retention of backup snapshots; privacy values are app-owned (architecture.md, section 2).
- *Separate backups.* All secrets are backed up once as their own encrypted off-disk backup with its own password; the data backup has its own. Of the backup credentials only these two passwords sit in the password manager, and a restore after a disk loss brings the secrets back first, then the data. The secrets backup does not exist yet: `~/.secrets` is in no backup today (architecture.md, section 6).

`backup/apps.toml` declares each app as a validated record (compose project, database service, dump kind,
database user and name, the Postgres major, the audio volume with the table that names its files, and
what the restore test asks the restored database). There is no hook language. Audio is optional and all
or nothing: Keycloak is DB-only. The database container and the volume are found by their
`com.docker.compose.*` labels; exactly one of each must match.

A SQLite app declares `dump = "sqlite_online_copy"`, the compose volume `database_volume`, the
`database_file` in that volume's root (one plain file name, no path) and the same `restore_test` table.
That form refuses the Postgres keys and audio, and a Postgres record refuses the SQLite keys.
A SQLite record may also declare one `files_volume` (a plain compose volume name, never `db` and never
`database_volume`) that is backed up beside the copy, and a `files_skip` (only with it): one name glob,
a plain prefix and exactly one trailing `*` (`staged-*`).

restic runs from the official image, pinned by version and digest (stages of `src/hal/backup/images/Dockerfile`, which Dependabot keeps current), with no
network, no capabilities and a read-only root, as your own user. Backup and restore test first check that
the pinned restic image, each Postgres app's restore image and, for a SQLite app, the pinned `sqlite`
stage (the python pin of `compose.yaml`) are present; `docker image prune -a`
removes them and the next run pulls them again by digest, failing early, before staging anything. The
password file is mounted read-only at `/run/secrets/restic-password` and handed to restic only as
`--password-file`; neither command ever reads, prints or logs it.

### Setup

The one-time setup is: `uv sync` (builds the `.venv` the units run); a restic password in
`~/.secrets/restic/password` (random, mode 0600, directory 0700); `hal backup --init` (creates
`~/backups/restic` once, mode 700); `loginctl enable-linger "$USER"` so the user timers run without a
login session; and `~/srv/hal/bin/hal setup`, which (after its `yes`) writes the units
(`hal-backup{,-restore-test}.{service,timer}`, declared in `src/hal/workstation/jobs.py`) into
`~/.config/systemd/user/`, reloads systemd and enables the user timers. The units expect the checkout at `~/srv/hal`.

Keep a copy of the password in the password manager or on paper. **Without it the repository cannot be
read by anyone, ever:** losing the key loses every backup, and restic has no recovery.

### Schedule and run now

| Timer | When | Does |
|---|---|---|
| `hal-backup.timer` | Sunday 03:00, `Persistent=true` | dump, count, back up; then, for each app that backed up, `forget --keep-weekly 4 --keep-monthly 3 --keep-tag pre-apply --prune --max-unused 0` and the forget of its pre-apply snapshots past 90 days; then `check`, whatever another app did |
| `hal-backup-restore-test.timer` | first Sunday of the month 05:00, `Persistent=true` | restore the last successful backup's snapshot, load and verify it; then `check --read-data-subset=10%` |

A missed run (PC off) runs at the next boot. If Docker or the app's database is not up yet, the backup
waits up to 10 minutes, then fails. One host lock (`~/.local/state/edge/backup.lock`) serialises every
`hal backup` or `hal restore` run: run by hand during a backup or restore test, `hal restore --list`,
`hal restore` or any other verb waits silently until that run ends. `hal restore <app> --live` holds
the lock from before its question to its end, so a Sunday backup or restore test that starts
meanwhile waits for the answer and the load.

To run now, start the same units the timers take (`systemctl --user start hal-backup.service` and
`hal-backup-restore-test.service`); the last `hal` event of the unit is the verdict.
`hal restore --list` lists the snapshots of host `hal` only. Both `forget` runs leave other hosts' snapshots alone.

Both units set `LOG_FORMAT=json`, the fleet's one log format. Read a run with
`journalctl --user -u hal-backup -p err` (`-o cat` prints the bare events); by hand the variable is unset
and `hal` prints rows. With `LOG_FORMAT=json` every row, verdict and error of `hal backup` and `hal restore --test` is one
flushed line: a journal priority (`<3>` error, `<4>` warning, `<6>` info) and a JSON object with
`timestamp`, `level`, `logger`, `service` and `event`. journald removes the priority; by hand, cut it
(`LOG_FORMAT=json hal backup | cut -c4- | jq`). Any other value than `json` or `text` stops every verb
with exit 2. A backup row's facts stand under `snapshot`, `bytes`, `seconds` and `reason`, any
other row's under `fact` (`pruned` keeps its word there, beside its `seconds`). On the timer path,
whose arguments are fixed, the events carry no host path, container id, argument or database row,
and the password is never read into one; restic's and Docker's own stderr stays raw in the journal.
`--json` stays the separate result for programs.

### One app, and the pre-apply snapshot

`hal backup <app>` and `hal restore --test <app>` work on that app alone: its dump, its
snapshot, its retention and its restore test. On a stand-in repository of a few MiB this took seconds; the structure check
and the prune (from the 11th pre-apply snapshot on, or once one is past 90 days) on the live repository are not measured. The
other apps' entries in the status file stay as they are, and a name `apps.toml` does not declare is refused before anything runs. The one-app
`hal restore --test` checks the repository's structure but does not read data (`check` without
`--read-data-subset`); the monthly run keeps that. Without a name both commands do what the timers do.
`hal restore --test <app> --snapshot <ID>` restores and verifies that snapshot of the app instead of
the one the status file names (it needs the app's name); `hal apply` uses it on the snapshot its own backup
just made, so a timer backup in between cannot swap the snapshot under test.

`hal backup <app> --pre-apply` additionally tags the snapshot `pre-apply`, and with
`--json` prints nothing but one object, `{"snapshot": "<ID>"}`, which `hal apply` reads (a failure is then one
`error: <app>: <reason>` line on stderr). It
keeps the last 10 pre-apply snapshots of that app (`forget --keep-last 10`, scoped to both tags),
without touching the app's other snapshots. The 10 apply per complete tag set: a snapshot with a
third tag forms another group and keeps its own ten. An app cannot be named `pre-apply`; `apps.toml`
refuses it. The weekly policy keeps every `pre-apply`
snapshot (`--keep-tag pre-apply`). Restore one with `hal restore <app> --snapshot <ID> --target <dir>`.

Every forget of an app forgets its pre-apply snapshots older than `PRE_APPLY_MAX_AGE`
(`src/hal/backup/restic.py`), 90 days (operator ruling 04.11.2026). A snapshot therefore stays until
the first successful forget of its app after it passes the bound, up to about a week longer with
healthy weekly backups. Every forget of an app, weekly and pre-apply, first runs its
policy, then lists the app's pre-apply snapshots of host `hal` (both tags) and forgets by full ID,
with its own `--prune`, each one taken before the host clock minus 90 days; when none is, no second
forget runs. The last 10 apply within the bound. Past it, a rollback through that snapshot is lost
(for Keycloak, an older realm state); the weekly snapshots stay.
Every prune keeps no unused data (`--max-unused 0`): it repacks each pack that still holds a
forgotten blob, so a forgotten snapshot's bytes leave the repository at that prune, and the bound
reaches them too. That repack on the live repository is not measured, like the prune itself.

The bound is measured on the host clock, and no guard checks that clock: one set far ahead makes
the age pass forget every pre-apply snapshot of each app forgotten in that run, irreversibly (the
weekly snapshots stay); one set far back makes it forget nothing until the clock is right. The age
pass never forgets a snapshot taken after the host clock. The policy forget before it still
applies: a pre-apply run keeps only the last 10 of the app, future-dated ones included, while a
weekly run keeps every pre-apply snapshot.

What the bound does not reach:

- An app whose backups keep failing keeps its snapshots, pre-apply ones included, until it backs up
  again; `hal check` names it `backup-stale` after 8 days and `hal alarm` mails it.
- An app that left `apps.toml` keeps its snapshots until the operator removes them; removing them is
  a deletion that waits for his word.
- The snapshots an earlier version wrote under its old host name keep their own exit (below).

### What a backup holds, and its limit

Every restic command that selects snapshots (`forget`, `snapshots --json`) is scoped to host `hal`, and a
forget by ID names only what such a listing found: `forget`
never thins an older snapshot of another host, and `hal restore` and `hal restore --test`
see only host `hal`, and so does `hal restore --list`. Snapshots that an earlier version wrote under host
`edge-backup` are invisible to hal and stay in the repository; they are deleted once
(`restic forget --host edge-backup --prune`, by a delegated agent) after every app has a `hal`
snapshot and `hal restore --test` has passed once (operator ruling 26.10.2026). Until then `hal restore`
refuses an app whose recorded snapshot is such an old one, and `hal backup` closes the gap. Until their
removal the old snapshots, pre-apply ones included, are kept beyond "4 weekly, 3 monthly".

Each snapshot (tag = app name, host `hal`) holds `db/db.dump` (`pg_dump --format=custom`,
transactional), `db/manifest.json` (the number of audio files counted just before the scan) and, for an
app with audio, `audio/` (the volume, read live). No service is stopped or started, so the backup is
crash-consistent: a file written during the scan may be missing or partial. The restore test catches
exactly that, so such a backup never counts as good.

A SQLite app's snapshot holds `db/db.sqlite3` instead of the dump, and `db/manifest.json` also names the
`rows` of the restore test's table in that copy. The copy is a consistent online copy, not a
crash-consistent one: a container of the pinned `sqlite` stage (no network, a read-only root, no
capabilities, the script `src/hal/backup/sqlite_copy.py` mounted read-only) runs as the database file's
owner with the volume mounted writable, because a WAL reader keeps its read lock in the `-shm` file. Its
connection is read-only, so it never writes or checkpoints the database file. It takes one read snapshot
with SQLite's backup API into memory and writes it to stdout, which becomes the staged file. It may create
and leave an empty `-wal` and a `-shm` beside the database, owned by the database owner with the file's
mode; the app's next last close removes them, and after a crash the copy rebuilds the `-shm` index. A
missing file fails the backup and creates nothing. Before restic stores it, the staged copy must pass
`PRAGMA integrity_check` with exactly `ok`: a bad copy fails in the phase `manifest` and never becomes the
last successful backup.

A SQLite app's `files_volume` lands in the snapshot as `<volume>/` beside `db/`, so `hal restore --target`
leaves both. The volume is mounted read-only into restic and read live, crash-consistent like audio.
The app must keep its files readable to your user through a read-only mount: restic runs as you, so an
entry you cannot read fails the backup (never skipped silently). Entries whose own name matches
`files_skip` are left out at every depth, by restic (`--exclude <volume>/**/<glob>`) and by the count
alike; nothing else is skipped. `db/manifest.json` also names the `files` counted just before the scan
(`find`, no network, a read-only root, your user), written only when a files volume is declared.
The database copy and the volume scan run seconds apart, so a run the app delivers in between may be
missing from the snapshot. Churn during the scan is loud or caught, and the next run retries: the count
fails the app in the phase `manifest` on a vanished entry or a directory it cannot enter; restic exit 3
(a path vanished or a file it cannot read) fails it in the phase `backup`.
A run removed whole before the count leaves a snapshot that is short by that run but consistent with its
manifest: the restore test compares the file count only, so it passes and cannot detect the loss.

Keycloak's dump holds its realm signing keys, the credential hashes and the client secrets. In the
repository it exists only encrypted. In plain text it exists in exactly three places, each mode 0700:
the staging directory during a backup, the restore test's directory during a restore test (both removed
when the run ends), and the target of `hal restore keycloak --target`, which you delete yourself.
If Keycloak is off or its database is down, the weekly run waits 10 minutes, reports keycloak as failed
and still backs up and forgets Songmaker and checks the repository; Keycloak's snapshots stay untouched
in that run.

LiteLLM's dump is its whole database `litellm`: each app key's hash, the person budget, the month
spend per key and per fingerprint, the daily rows and the tool names, and `key_name`, the fragment
LiteLLM shows of each key; never a key in clear. In plain text it exists in the same three 0700
places as Keycloak's. LiteLLM writes spend to its database in batches every 10 seconds
(`PROXY_BATCH_WRITE_AT`), so a dump lacks at most that last batch.

presentator's copy is its SQLite database and its built decks (`builds`, without the half-built
`staged-*` directories). The database holds the people's sessions, their Keycloak `sub`s and the
source secrets, which are encrypted with presentator's master key (the file
`~/.secrets/presentator/secret-key`). The master key is not in the data backup, so a restored copy
cannot read those secrets without it. Until the separate backups of secrets and data of #291 exist,
the master key and the data backups sit on the same disk. The session ids (the session cookie
values) and the Keycloak refresh and ID tokens are stored as plain text in the copy: whoever holds a
staged, restored or `--target` copy can take over live sessions and refresh Keycloak tokens. In plain
text the copy exists in the same three 0700 places as Keycloak's.

A row that `hal expire` deletes ([agent-service.md](agent-service.md), „What expires“) stays in
every snapshot taken before the delete, until retention forgets that snapshot:

- a weekly snapshot is kept while it is one of the last 4 weekly or 3 monthly ones (`KEEP_WEEKLY`,
  `KEEP_MONTHLY` in `src/hal/backup/restic.py`), so at most about ten weeks after the delete;
- a pre-apply snapshot is kept until 10 newer pre-apply snapshots of its app replace it
  (`KEEP_PRE_APPLY`) or until its app's first successful forget after it is older than
  `PRE_APPLY_MAX_AGE`, whichever comes first (above, „One app, and the pre-apply snapshot“);
- both hold only while the app's own runs succeed: a failed app is not forgotten, the others are,
  and restic counts weeks and months that have snapshots, so an app that is no longer backed up
  keeps its last ones.

### The restore test

It restores the last successful backup's snapshot into a private directory under `~/.cache/edge-backup`
and checks:

- `pg_restore --list` reads the dump;
- the dump loads with `pg_restore --exit-on-error --single-transaction` into a throwaway PostgreSQL
  container without network, of the major the app's database runs (16 for Songmaker, 17 for Keycloak
  and LiteLLM),
  each image a stage of `src/hal/backup/images/Dockerfile`; the pin of major 17 equals `keycloak-db` in
  `compose.yaml` and a test fails when they differ. The server's diagnostics are discarded because
  PostgreSQL quotes row values in them: a failure shows the step and the exit code only;
- the row count of the app's table (`songs`, Keycloak's `realm`, LiteLLM's
  `LiteLLM_VerificationToken`) answers; for Keycloak and LiteLLM (`require_rows = true`) it is above
  zero: a LiteLLM without a key is no backup;
- for a SQLite app there is no throwaway server: a container of the `sqlite` stage mounts only the
  restored directory, read-only, and the file passes `PRAGMA integrity_check` with exactly `ok` and its
  table holds the manifest's `rows` (a manifest without `rows` fails; `require_rows` applies as above);
- for a SQLite app with a files volume: the restored `<volume>/` is a directory and its file count,
  taken by the same rule in a container that mounts no volume, equals the manifest's `files` (a manifest
  without `files` fails);
- for an app with audio: the restored audio file count equals the manifest's, and every audio file the
  restored database references (`generations.mp3_path`) exists in the copy with a size above zero.

The throwaway server is named `hal-backup-restore-test-<8 hex>`, the first 8 hex digits of the sha256
of the home's lock file path, and carries the label `hal-backup.role=restore-test`. A run removes only
its own home's container of that name and label, before it starts and when it ends, so a run under
another HOME (a probe's) never removes this home's server; the lock serialises the runs of one home.

The restore test never touches a live database or volume. (The SQLite backup's copy only reads the
database file, as described above.) Backup and restore test stage their plaintext in
`~/.cache/edge-backup` and remove it when they end. A run killed outright cannot, so the plaintext stays
until the next backup or restore test, which removes it first; that sweep removes only directories a run
marked as its own.

### Status

`~/.local/state/edge/backup-status.json` is written atomically at every phase (schema 2; the shape is in
`src/hal/backup/`). The run's verdict stands at the top (`state`: `running`, `ok` or `failed`, with
`phase`, `failing_phase`, `failing_app`, `exit_category`, `last_attempt`); each app (its name, which is
also its restic tag) has its own last good snapshot and times. The file holds no output, command line,
path or file name.

- A `running` that outlasts the timer's 6-hour limit means the run died: treat it as failed.
- `exit_category` is one of `configuration`, `not-ready`, `command-failed`, `verification-failed`,
  `interrupted`, `internal`; `failing_app` is `null` for a failure that belongs to no app.
- When the backup succeeded but prune or check failed, the apps' backup times have moved on and
  `state` is `failed`, with `failing_phase` `forget` or `check` and no `failing_app`, also after an
  app failed: a failed forget or check is the run's verdict, otherwise the first failed app is.
- An app that fails does not stop the others, and each app's snapshot is recorded right after its own
  `restic backup` exits 0, so earlier successes stay. A failed app is not forgotten in that run, so
  its recorded snapshot stays. An app
  removed from `apps.toml` keeps its entry; renaming an app makes it a new app.
- A status file that cannot be read (mode 000, corrupt JSON, an unknown `schema`) is never overwritten:
  backup, restore test and restore fail with one line and exit 3. Past successes are never
  replaced by nulls; repair or remove the file by hand to go on.
- A schema-1 file is read into this shape: its id and times go to the declared app only when exactly one
  app is declared and restic confirms the id in that app's tag scope; otherwise they stay in an
  `unattributed` entry and `restore` asks for `--snapshot`. `restore` never writes the file. A runner
  from before schema 2 refuses a schema-2 file like any unknown one: move the file aside, then restore by
  `--snapshot` or run the next backup.
- The single-app runs (`hal backup <app>`, `hal restore --test <app>`) write the same file: `state` reflects
  the latest run of either form, and the data-reading check belongs only to the full run without an app.
- `state` describes the latest run of either command: a failed Sunday backup followed by a passing
  restore test reads `ok`, and a timer that never fires leaves the last `ok` standing. A reader judges
  freshness per app: `last_successful_backup` no older than about 8 days,
  `last_successful_restore_test` no older than about 5 weeks.

`hal backup` prints a row per app (`✓ <app>  backed up  <snapshot> · <size> · <time>` or `✗ <app>  not backed up  <reason>`;
a failed app does not stop the others; the size is restic's `total_bytes_processed`, the source size, and the time is the app's whole span from readiness to the status write; a backup summary without the id or the size fails the app), then `· <app>  not pruned  its backup failed` per failed app, a `repository` row (`✓ repository  pruned  checked · <time>` after forget and check, the time being their span; `✗ repository  not pruned  <reason>`
when a forget failed, `✗ repository  not checked  <reason>` when the check did; none when every app of the run failed or the repository is unusable) and, on success, `✓ backup done · N apps · <time>`.

`hal restore --test` prints the same way: `✓ <app>  restore proven  <snapshot>` or `✗ <app>  not proven  <reason>`
per app, `✓ repository  checked` (`✗ repository  not checked  <reason>` when the check failed after an app
failed) and, on success, `✓ restore test done · N apps · <time>`; a failed app ends with `error: <app> not proven`
when one app ran, or `error: 1 of N apps not proven` when several did, and `next: hal restore --test <app>`; with
`--snapshot` (one app, the realm step's call) it ends with `error: <app>: <reason>` instead.

Exit 0: every phase succeeded. Exit 3: a run failed; `error: <app> not backed up · last good backup DD.MM. HH:MM` when one app ran, or
`error: 1 of N apps not backed up · <app>'s last good backup DD.MM. HH:MM` when several did, with `next: hal backup <app>` after the rows
(the first failed app's `last_successful_backup` from the status file, in local time and with the year when it is not this one; without one the fact reads `<app> has no good backup recorded`, or `no good backup recorded` when one app ran;
`--pre-apply --json` keeps `error: <app>: <reason>`), or `error: <reason>` when the run failed before any app or in its forget or check
(`hal restore --list`, the real `hal restore`, `hal backup --init` and `--unlock` still print `error: hal <verb>: failed: …`). Exit 2: the flags do not fit together (`--pre-apply` without an app, for
example); nothing ran. Exit 130: Ctrl-C or SIGTERM; `backup` and the restore test record it in the status file as interrupted.

`hal restore <app> --live` ends with `✓ <app>  loaded  <snapshot> · <time>` and `next: hal start <app>`, exit 0.
Exit 4: the app is on (`stop it first: hal stop <app>`), disabled or no unit, there is no terminal,
a `pg_restore` session still runs in its database, or its switch changed after the check. Exit 1: the
question was answered with anything but `yes`. Exit 3: the record keeps audio or files, or a step before
the load failed (`error: <app>: <reason>`), or the load failed. A failed load ends in one line,
`error: <app> load failed · <cause> · a rerun loads the snapshot whole`, and
`next: hal restore <app> --live --snapshot <id>` naming the snapshot it tried. What the cause means for
the data:

- `pg_restore ended with exit N`, or `the shell could not start pg_restore`: `pg_restore`'s
  transaction rolled back, so the old data stays, unless the server crashed at the commit;
- `no exit code of pg_restore`, or the client's own exit: the load may be in, since `pg_restore`
  commits whenever the whole dump reached it.

In every case the rerun the line names, of the same snapshot, is the way back. `hal start <app>` on
the old data is your own choice, and only after a printed code other than 0. Ctrl-C or SIGTERM before
the load ends with `interrupted · nothing loaded`, exit 130; during the load hal waits for the load's
end and prints its real outcome.

### Restore one app

Songmaker's block below stays until its live restore exists (`docs/architecture.md` gap 18;
follow-up on overnightworks/edge#222): it copies audio, which `hal restore <app> --live` does not.

```sh
hal restore songmaker --target ~/restore-songmaker   # a new directory, not under ~/.cache/edge-backup
```

It restores the snapshot of that app's **last successful backup**
(`apps.<app>.last_snapshot_id` in the status) and prints its short ID, never a
newer snapshot that a failed run left behind (restic exit 3 leaves a partial
one). `hal restore` refuses with one line and exit 3, names the newest
snapshot and says how to choose it, in two cases: no successful backup of that
app is recorded yet, or the recorded snapshot is missing in the repository.
The restore test verifies each app against its own last good snapshot and
refuses the same way; a failed `check --read-data` gives no app a new time.

Disaster recovery on a machine without the status file: list the `hal` snapshots
with `hal restore --list`, then choose a snapshot of that app by the
first 8 or more characters of its ID:

```sh
hal restore songmaker --snapshot 1a2b3c4d --target ~/restore-songmaker
```

An ID that is unknown, ambiguous, another app's or from another host is refused
with one line. The target holds
`db/db.dump` and `audio/`. Loading them into the live app is a deliberate
manual step. Stop every Songmaker container except its database,
load the dump, copy the audio back into the volume, start them again. Paste the
block as a whole: it runs in a subshell that stops at the first failing command,
so a failed load or copy never goes on to the other half or restarts the app:

```sh
(
set -euo pipefail
restored=~/restore-songmaker
# The copy runs in the backup runner's own restic image, pinned by version and digest: no
# unpinned image ever gets write access to the live audio volume.
image=$(cd ~/srv/hal && .venv/bin/python -c \
  'from hal.backup.settings import RESTIC_IMAGE; print(RESTIC_IMAGE)')
pg=$(docker ps --quiet --filter label=com.docker.compose.project=songmaker \
  --filter label=com.docker.compose.service=postgres \
  --filter label=com.docker.compose.oneoff=False)
[ "$(wc -w <<<"$pg")" -eq 1 ] \
  || { echo "need exactly one Songmaker database container, found: ${pg:-none}" >&2; exit 1; }
stopped=$(docker ps --quiet --filter label=com.docker.compose.project=songmaker \
  | { grep -vx "$pg" || true; })
[ -n "$stopped" ] || { echo "no running Songmaker container to stop" >&2; exit 1; }
docker stop $stopped
docker exec -i "$pg" pg_restore --username songmaker --dbname songmaker \
  --clean --if-exists --single-transaction --exit-on-error < "$restored/db/db.dump"
docker run --rm --network none \
  --mount type=bind,source="$restored/audio",target=/from,readonly \
  --mount type=volume,source=songmaker_audiofiles,target=/to \
  --entrypoint cp "$image" -a /from/. /to/
docker start $stopped
)
```

When it stops, Songmaker stays down; `docker stop` printed the IDs of the
containers it stopped. A failed load changed nothing (`--single-transaction`),
so `docker start` with those IDs brings the old state back. After a failed copy
the database is already restored: fix the cause and copy again before you start
them.

`cp -a` adds and overwrites; audio written after the snapshot stays in the
volume. The copied files keep the owner restic restored them with (your user).

### Restore Keycloak

Only you restore Keycloak. `hal restore keycloak --live` loads the last good snapshot into
Keycloak's live database in one transaction, after you type `yes` at a terminal, and only while
Keycloak is switched off. It starts `keycloak-db` alone if it is stopped, leaves `keycloak` stopped,
holds the backup lock and removes the restored dump when it ends:

1. `hal stop keycloak`
2. `hal restore keycloak --live`, and check that its loaded row names the snapshot you meant
3. `hal start keycloak`

A failed realm step of `hal apply` names its pre-apply snapshot; load that one with
`hal restore keycloak --live --snapshot <ID>`. A failed load's line names its own rerun (above).

A run killed outright (SIGKILL, the terminal closed) reports nothing: its load ends whole or not
at all, nobody reports which, and Keycloak stays stopped. Run
`hal restore keycloak --live --snapshot <id>` with the ID the killed run's question named (or
`hal restore --list`'s): it refuses while that load still runs, then loads.

### Restore LiteLLM

The same three commands load LiteLLM's database:

1. `hal stop litellm`
2. `hal restore litellm --live`
3. `hal start litellm`

Every key and person then counts from the snapshot's spend: one past its budget stays refused, and
spend since the snapshot is lost. A snapshot from an earlier month is reset by LiteLLM's own budget
job, as its `budget_reset_at` has passed. No app reaches LiteLLM while it is switched off.

### A lost LiteLLM volume

At its next start `litellm-db` is empty and LiteLLM migrates it. The key step of `hal apply` then
makes the person budget and each app's key anew from the key files (when it runs:
[agent-service.md](agent-service.md), „The API route“). Every budget restarts at zero, and the
daily rows are gone. `~/.secrets` is in no backup. `hal restore litellm --live` loads the last
backup into the live database and gives the month's spend back („Restore LiteLLM“ above). The key
files must be the ones that made the hashes.

### Stale locks

The host lock frees itself when the process ends. A restic lock left by a killed run is removed
with `hal backup --unlock`, but only once it is stale: every container is host `hal` with
restic as PID 1, so restic counts the lock stale only after 30 minutes. Until then `unlock` leaves it,
and a new run waits up to 5 minutes for it, then fails. No command ever runs with `--no-lock`.

### The old backup

`~/backups/songmaker` (unencrypted) is left untouched. The operator deletes it after the first
successful backup and restore test (home-tools#20).
