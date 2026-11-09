# Never built: the pins of the images `hal backup` runs, one stage each, read by hal.backup.settings
# and kept current by Dependabot's docker ecosystem. Major 17 equals compose.yaml's keycloak-db pin, the sqlite stage its python pin.
FROM restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510 AS restic
FROM postgres:16.15-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139 AS restore-16
USER postgres
FROM postgres:17.11-alpine@sha256:3540c0362c809df084ffac0ae69fe794515f9de92692f02178bcdce0ef0302ac AS restore-17
USER postgres
FROM python:3.14.10-alpine@sha256:a18b20ad69e74df6cf6d2e1b1a260d7a1ecf5380fd83b310f83ba88c461cf894 AS sqlite
USER nobody
