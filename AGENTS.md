# hal

## Checks

CI runs the `check` job (lint, tests, wheel smoke test) and, after it, the `quality` job: the shared
gate of overnightworks/quality (`quality/config.toml` names the mandatory
jobs). Its required check is `quality / verdict`; the gate's SonarCloud scan is
the one scanner, and it reads `sonar-project.properties` and the tests job's
`coverage` artifact.

Before pushing, after the last merge of main, a builder or fixer runs the gate's pinned check:
`uvx --from "git+https://github.com/overnightworks/quality@2d2b68bf3916b34f6f2c72a540c1e3d8a947b750" quality check`
Its closing line starts with `✓ clean`.

## Commits

Never pass `--no-verify` to `git commit` or `git merge`. The global hook that
`hal setup` installs scans `git commit` and merge commits for secrets; the
section „Was der Hook nicht garantiert“ of `docs/home.md` lists what it does not cover
(rebase, cherry-pick, `--no-verify` and more), and the agent rule is the
backstop for the flag git lets skip it. A refused commit is fixed by
removing the secret, not by bypassing the hook.
