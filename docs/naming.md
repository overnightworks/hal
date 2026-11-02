# Naming

The one owner of how overnightworks repositories, tools, packages and units are
named. Decided by the operator on 16.10.2026 (overnightworks/edge#24); the plan
and the verification log stay in that issue.

## The rule

Every repo has one canonical stem: a lowercase word, or a hyphenated pair when
one word would mislead. Every name the repo owns is derived from that stem by
the table below, and nothing else picks a name of its own. The repo's role
lives only in the property `role`.

| Namespace | Derived form | Why this form |
|---|---|---|
| GitHub repo, local clone, worktrees | `<stem>`, `~/git/<stem>`, `~/git/<stem>-worktrees/issue-<n>-<slug>` | the contract's worktree rule then names one thing |
| Python distribution | `overnightworks-<stem>`; a repo with several: `overnightworks-<stem>-<component>` | never takes or shadows a PyPI name (the `overnightworks-...` names are free; the bare names `aco`, `home`, `quality`, `edge`, `atelier`, `agent-runtime`, `webauth`, `kiln`, `claudebot`, `gmail-cleanup` are taken) |
| Python import | `<stem>` with `-` to `_`; component `<stem>_<component>` | a valid identifier. The prefix does not prevent import clashes, so each change checks for them (below) |
| CLI | `<stem>`, and features are subcommands. A component with its own distribution has the entry point `<stem>-<component>` | one command per repo; a separately installed process stays visibly part of it |
| systemd unit, compose service | `<stem>` or `<stem>-<job>` | `systemctl list-units '<stem>*'` finds them all |
| platform unit in `fleet.yaml` | the catalog key equals the compose profile name (`step-ca`, `keycloak`) | `hal apply --local` switches the profile of that name; a key without a profile is refused |
| app in `fleet.yaml` (an entry with `repo` and `run`) | the catalog key equals the repository name under `github.org`, its compose project and its checkout `~/srv/<key>`; no edge compose profile and not `edge` | `hal apply` switches the project of that name on at the repository's newest release; a key that names an edge profile or a project name that cannot be a repository is refused |
| platform deploy checkout | `~/srv/hal`; no app key may be `hal` | `hal apply` runs only from there; the app checkouts `~/srv/<key>` live beside it |
| Sonar project key | `overnightworks_<stem>` | SonarCloud's org-key form |
| MCP origin host | `<stem>.mcp.internal`, the stem of the app's repository | the name `traefik-mcp` routes on and answers to, and the only suffix `step-ca/ca.json` issues for (edge#37) |
| CSS / release asset | `<stem>.css`, `<stem>-<version>...` | |
| Hosts, Keycloak groups and clients | **not derived; unchanged** unless the job changes | external identities. A renamed group in the YAML creates a new group and leaves the old one with its memberships (the apply deletes no undeclared top-level object and no person), and a renamed client changes the token audience |
| Ecosystem-dictated names | the ecosystem's form with the stem inside: Slidev `slidev-addon-<stem>`, Claude/Codex plugin `<stem>` | the ecosystem finds them only that way |

GitHub topics are to be derived from the planned service catalog `fleet.yaml`
by OpenTofu and never set by hand (overnightworks/edge#20, building block 5).
The file exists (`fleet.yaml`); its topics follow with overnightworks/edge#30, and until then
topics are not set at all.

### Import clashes

They matter only inside one environment. Tools (`aco`, `hal`, `quality`)
run in their own uv environments. Only the libraries (`webauth`,
`agent_runtime*`) enter foreign environments. Each change proves its import
with `python -I -c "import X; print(X.__file__)"` resolving into our tree, and
with no foreign distribution named like the import in the affected `uv.lock`
files.

### Fixed points

- songmaker and hopin keep every name they have, including their unprefixed
  distributions `songmaker` and `hopin`. Both names are free on PyPI and run
  only from their own checkout. Their Sonar keys `overnightworks_songmaker`
  and `overnightworks_hopin` already follow the rule. songmaker's units
  (`songmaker`, `songmaker-autodeploy`, `songmaker-cli-credentials-mirror`,
  `songmaker-alert@`) and compose services (`songmaker-web`,
  `songmaker-music-worker`, `songmaker-scoring-worker`) stay as they are. Their
  clone and worktree paths (`~/git/songmaker`, `~/git/hopin`, `-worktrees/`)
  already follow the rule.
- ACE-Step-1.5 is upstream and keeps its upstream names.

## Target mapping per repository

A check mark means the name already conforms. The repo and `~/git/<stem>` are
always the stem.

The `hal` command's name and verbs have one code owner, `hal.output.command`; every command text in `src/` is built from it, and `tests/test_output_command_texts.py` turns a hand-written `hal <verb>` red.

| Stem (was) | Distribution(s) | Import(s) | CLI | Units / compose | Sonar key | Hosts and Keycloak (unchanged) |
|---|---|---|---|---|---|---|
| `aco` (agent-coordination, dir `agent-claim`) | `overnightworks-aco` | `aco` (`aco.board`) | `aco`, `aco serve` | none | `overnightworks_aco` | none until AC2, then `/apps/aco` |
| `hal` (was `edge` and `home`) | `overnightworks-hal` ✓ | `hal` ✓ (`hal.stack`, `hal.backup`, `hal.exposure`, `hal.output`, `hal.workstation`) | `hal` ✓ | `hal-backup`, `hal-backup-restore-test`, `hal-check` ✓; compose `edge` (H5i renames it) | `overnightworks_hal` | `auth.hallucinai.de` |
| `quality` ✓ | `overnightworks-quality` | `quality` | `quality` | check `quality / verdict` ✓ | ✓ | none |
| `atelier` (marketplace) | `overnightworks-atelier` (dev only) | none | plugin and marketplace `atelier` ✓ | none | `overnightworks_atelier` | none |
| `webauth` ✓ | ✓ | ✓ | none | none | ✓ | none |
| `agent-runtime` (agent-providers) | `overnightworks-agent-runtime`, `overnightworks-agent-runtime-client`, `overnightworks-agent-runtime-service` | `agent_runtime`, `agent_runtime_client`, `agent_runtime_service` | `agent-runtime-service` | none | `overnightworks_agent-runtime` | client `agent-service` |
| `appkit` (ui-style) | `overnightworks-appkit`; npm `overnightworks-appkit` | `appkit` | none | none | `overnightworks_appkit` | none |
| `presentator` (agent-presentator) | `overnightworks-presentator`, `overnightworks-presentator-copresenter`, `overnightworks-presentator-speech`; npm `slidev-addon-presentator` ✓ | `presentator` ✓, `presentator_copresenter`, `presentator_speech` | `presentator`, `presentator-copresenter`, `presentator-speech` ✓ | `presentator-copresenter`, `presentator-speech` ✓ | `overnightworks_presentator` | `presentator.hallucinai.de`, `/apps/presentator` |
| `redphone` (claudebot) | `overnightworks-redphone` | `redphone` | none | `redphone` (was `agent-telegram`) | `overnightworks_redphone` | none |
| `gmail-cleanup` ✓ | `overnightworks-gmail-cleanup` | ✓ | none | none | ✓ | none |
| `kiln` ✓ | unpublished Rust crates `kiln-<component>` ✓ | none | none | none | none | none |
| `songmaker`, `hopin`, `ACE-Step-1.5` | unchanged (fixed point, upstream): `songmaker`, `hopin` | | | songmaker: see Fixed points | `overnightworks_songmaker`, `overnightworks_hopin` (already conform) | `songmaker`, `/apps/songmaker`, `/apps/hopin` |
| `atelier-1` (the archived former atelier) | archived, renamed so marketplace can take `atelier` | none | none | none | none | none |
| `atelier-2`, `foreman` (archived) | unchanged | none | none | none | none | none |

Rulings of overnightworks/edge#24 recorded in the table:

- The archived `atelier` becomes `atelier-1`; `atelier-2` and `foreman` stay as
  they are.
- claudebot becomes `redphone` (ruled 16.10.2026: the red telephone home, his
  emergency chat with the PC). It bridges Codex too, so "claude" was wrong.
- `presentator` stays as a deliberate brand: host, Keycloak group, units and
  import already use it, and renaming would lose group memberships.

## Hand procedures

### P1: repository rename

1. Before: `aco status` in that repo shows no claim and no live lane other than the rename's own (P2 step 1).
2. The operator approves; an agent runs `gh repo rename` (for a repository with
   `sonar-project.properties`, after P2 steps 1-2).
3. The operator runs `hal rename OLD NEW` in their own terminal: it shows the moves, asks
   `Type yes`, then moves (`--dry-run` only shows; an agent without a terminal can only
   `--dry-run`).
   It moves every clone under `~/git` and its `-worktrees`, repairs the
   worktrees, sets `origin` to the new name (never re-clone: the local
   `refs/aco/state` and its fetch refspec must survive; aco reads the identity
   from the remote URL first and uses `gh repo view` only as a fallback),
   carries the Claude project memory, sets the `origin` of a deploy checkout
   outside `~/git` and, in every clone and worktree with a `uv.lock`, runs
   `uv venv --allow-existing` and `uv sync --locked --reinstall` on every run,
   so a moved `.venv` names its new path and a rerun finishes a half-built one;
   `uv venv` gets the venv's own Python minor version (3.12 stays 3.12; the patch
   release and the interpreter install it comes from may change). It deletes nothing.
   It refuses, changing nothing, while a process runs inside a clone, a target
   exists, a symbolic link lies in any path it reads or acts on (the home directory
   included: a clone, a worktree inside or outside `~/git` as git lists it, a `.venv`
   or a target path), or a link in `~` or `~/srv` points to a checkout of this
   repository outside the moved clones, or GitHub does not know the new name. `hal rename NEW OLD` undoes it and asks its own yes.
   A step that fails stops it, names the step and what is done; run the same
   command again once the cause is fixed and it finishes the half-moved clones.
4. It reports, exit 1, the user units, links in `~/.local/bin`, `~` and `~/srv`
   and uv tools that point into a moved clone; the repository's own head fixes those (a rerun of
   `hal setup` from the moved clone re-points its `~/.local/bin/hal`; reinstall
   uv tools from the new path).
5. Update the repo description and the callers' URLs (git URLs redirect in the
   meantime).

GitHub redirects git and web URLs, but **not** calls to actions and reusable
workflows in a renamed repo: move those callers first.

### P2: Sonar key and binding

Repos with `sonar-project.properties` (and a bootstrap workflow, where one
exists):

1. The agent opens the PR that carries the rename's other changes, green under the
   old name; the key commit stays local (pushed under the old name it fails the
   gate's preflight), and other merges are held.
2. An agent disables the repository's CI workflow (`ci` here) and drains it: it
   lists every unfinished run (any status but completed) over all pages and
   waits until each is completed or cancelled, listing again until none is
   left. This happens before the first identity change in either direction;
   the workflow is enabled again only once the GitHub name and the Sonar key
   agree. Going back, SonarCloud's key changes back before the GitHub name.
3. The operator runs Administration, Update Key, once the project's Background
   Tasks show nothing pending or in progress.
4. An agent enables the workflow and pushes the key commit onto that PR; once the
   verdict is green, it merges the PR.
5. The operator re-saves the binding.

Automatic-analysis repos: Update Key and binding on the server only.

Check: main's analysis lands in the new key, and `api/components/search` shows
no project with the old key. A project there would mean a scanner re-created
it.

### P3a: unit renamed (new name, new file)

1. Install the new unit file and `daemon-reload`.
2. `disable --now` the old name, then `enable` the new one (and `enable --now`
   its timer, if any).
3. Verify the old name is gone: `systemctl --user list-unit-files '<old>*'` is
   empty and `systemctl --user cat <old>` fails.
4. Verify the new unit as in P3b. Long-running services: `is-active` is
   `active` and the journal shows a clean start.

### P3b: unit kept, ExecStart or WorkingDirectory changes

1. Edit the unit and `daemon-reload`.
2. Activate the new command:
   - an inactive `Type=oneshot` service runs once with
     `systemctl --user start <unit>`;
   - a long-lived service that is running uses `systemctl --user restart <unit>`,
     because `start` would leave the old process running with its old command.
3. `Type=oneshot` services need not be `active` afterwards, so `is-active`
   proves nothing. Check `systemctl --user show -p Result,ExecMainStatus <unit>`:
   `Result=success` and `ExecMainStatus=0`.
4. For its timer: `systemctl --user is-active <timer>` is `active`, and
   `systemctl --user list-timers <timer>` shows a next run.
5. Long-running services: after the restart, `is-active` is `active`,
   `systemctl --user show -p ExecMainStartTimestamp,ExecStart <unit>` shows a
   start after the restart and the new command, and the journal has a clean
   start line.
