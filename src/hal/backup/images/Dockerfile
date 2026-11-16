# Never built: the pins of the images `hal backup` runs, one stage each, read by hal.backup.settings
# and kept current by Dependabot's docker ecosystem. Major 17 equals compose.yaml's keycloak-db pin, the sqlite stage its python pin.
FROM restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510 AS restic
FROM postgres:16.15-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139 AS restore-16
USER postgres
FROM postgres:17.11-alpine@sha256:e5d2edd28b1f8d40a0a6c0c9cdc545b19b56a0d5d88f94bc11a97d970d4700d0 AS restore-17
USER postgres
FROM python:3.14.10-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67 AS sqlite
USER nobody
