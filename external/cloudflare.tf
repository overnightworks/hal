# Cloudflare as found: each host of local.hosts gets a proxied CNAME to its tunnel and, when it
# bypasses or protects, an Access app. Everything is looked up at plan time, so no ID is typed or
# stored twice; live records and apps are imported as found and nothing is converted (D12).
locals {
  operator_group_name = "operator"

  protected_hosts = { for fqdn, host in local.hosts : fqdn => host if host.exposure == "protected" }
  access_app_hosts = {
    for fqdn, host in local.hosts : fqdn => host if contains(["bypass", "protected"], host.exposure)
  }

  zone_id    = data.cloudflare_zone.this.id
  account_id = data.cloudflare_zone.this.account.id
  tunnel_id  = data.cloudflare_zero_trust_tunnel_cloudflared.this.id

  named_tunnel_ids = { for name, tunnel in data.cloudflare_zero_trust_tunnel_cloudflared.named : name => tunnel.id }
  # A record's tunnel is its host's; a redirect-only name has no host and keeps hal's.
  record_tunnel_ids = {
    for fqdn in local.record_fqdns : fqdn => (
      try(local.hosts[fqdn].tunnel, null) == null ? local.tunnel_id : local.named_tunnel_ids[local.hosts[fqdn].tunnel]
    )
  }

  operator_group_ids = [
    for group in flatten(data.cloudflare_zero_trust_access_groups.operator[*].result) : group.id
    if group.name == local.operator_group_name
  ]
  operator_group_id = length(local.operator_group_ids) == 1 ? local.operator_group_ids[0] : null

  # Every name that answers at the edge: the tunnel's hosts and the redirected names. A redirected
  # name has a record and no line in hal's ingress unless it is also a host on hal's tunnel; a host on another tunnel has its line in
  # that tunnel's ingress.
  redirect = try(local.fleet.cloudflare.redirect, null)
  redirect_fqdns = [
    for name in try(local.redirect.hosts, []) : name == "@" ? local.fleet.cloudflare.zone : "${name}.${local.fleet.cloudflare.zone}"
  ]
  record_fqdns = toset(concat(keys(local.hosts), local.redirect_fqdns))

  # Among these types at a host's name only a single CNAME may exist (D12: no conversion).
  address_record_types = ["A", "AAAA", "CNAME"]
  address_records = {
    for fqdn in local.record_fqdns : fqdn => [
      for record in data.cloudflare_dns_records.host[fqdn].result : record
      if contains(local.address_record_types, record.type)
    ]
  }
  record_ids_to_import = {
    for fqdn, records in local.address_records : fqdn => "${local.zone_id}/${records[0].id}" if length(records) == 1
  }
  app_ids_to_import = {
    for fqdn in keys(local.access_app_hosts) :
    fqdn => "accounts/${local.account_id}/${data.cloudflare_zero_trust_access_applications.host[fqdn].result[0].id}"
    if length(data.cloudflare_zero_trust_access_applications.host[fqdn].result) == 1
  }
}

# The provider itself fails on no or several matching zones and tunnels (C13); hal's tunnel is the
# live one with hal's id, another one the live one with the name a host gives. The zone and hal's
# tunnel are looked up with no host too: the tunnel's configuration outlives the last host.
data "cloudflare_zone" "this" {
  filter = { name = local.fleet.cloudflare.zone }
}

data "cloudflare_zero_trust_tunnel_cloudflared" "this" {
  account_id = local.account_id
  filter     = { uuid = var.tunnel_id, is_deleted = false }
}

data "cloudflare_zero_trust_tunnel_cloudflared" "named" {
  for_each   = toset([for host in local.hosts : host.tunnel if host.tunnel != null])
  account_id = local.account_id
  filter     = { name = each.key, is_deleted = false }
}

data "cloudflare_dns_records" "host" {
  for_each = local.record_fqdns
  zone_id  = local.zone_id
  name     = { exact = each.key }

  lifecycle {
    postcondition {
      condition = (
        length([for record in self.result : record if record.type != "CNAME" && contains(local.address_record_types, record.type)]) == 0
        && length([for record in self.result : record if record.type == "CNAME"]) <= 1
      )
      error_message = join(" ", [
        "${each.key} already has ${join(", ", [for record in self.result : record.type if contains(local.address_record_types, record.type)])} records.",
        "Only a single CNAME can be adopted; converting a record is not supported (D12)."
      ])
    }
  }
}

# `exact` keeps the apex lookup from matching the wildcard app by substring.
data "cloudflare_zero_trust_access_applications" "host" {
  for_each   = local.access_app_hosts
  account_id = local.account_id
  domain     = each.key
  exact      = true

  lifecycle {
    postcondition {
      condition     = length(self.result) <= 1
      error_message = "${each.key} matches ${length(self.result)} Access apps; exactly one can be adopted."
    }
  }
}

data "cloudflare_zero_trust_access_groups" "operator" {
  count      = length(local.protected_hosts) > 0 ? 1 : 0
  account_id = local.account_id
  name       = local.operator_group_name
}

# The Access policy a host's exposure asks for exists only while a host uses it.
resource "cloudflare_zero_trust_access_policy" "bypass" {
  count      = anytrue([for host in local.access_app_hosts : host.exposure == "bypass"]) ? 1 : 0
  account_id = local.account_id
  name       = "bypass"
  decision   = "bypass"
  include    = [{ everyone = {} }]
}

resource "cloudflare_zero_trust_access_policy" "allow_operator" {
  count      = length(local.protected_hosts) > 0 ? 1 : 0
  account_id = local.account_id
  name       = "allow ${local.operator_group_name}"
  decision   = "allow"
  include    = [{ group = { id = local.operator_group_id } }]

  lifecycle {
    precondition {
      condition     = length(local.operator_group_ids) == 1
      error_message = "A protected host needs exactly one Access group named ${local.operator_group_name}; found ${length(local.operator_group_ids)}."
    }
  }
}

resource "cloudflare_zero_trust_access_application" "host" {
  for_each     = local.access_app_hosts
  account_id   = local.account_id
  name         = each.key
  domain       = each.key
  type         = "self_hosted"
  destinations = [{ type = "public", uri = each.key }]
  policies = [{
    id         = each.value.exposure == "bypass" ? one(cloudflare_zero_trust_access_policy.bypass[*].id) : one(cloudflare_zero_trust_access_policy.allow_operator[*].id)
    precedence = 1
  }]
}

# Protection before reachability: no record exists before the apps, the public deny and the
# redirect do (and none outlives them).
resource "cloudflare_dns_record" "host" {
  for_each   = local.record_fqdns
  zone_id    = local.zone_id
  name       = each.key
  type       = "CNAME"
  content    = "${local.record_tunnel_ids[each.key]}.cfargotunnel.com"
  proxied    = true
  ttl        = 1
  depends_on = [cloudflare_zero_trust_access_application.host, cloudflare_ruleset.deny_public, cloudflare_ruleset.apex_redirect]
}

# HSTS at the zone's edge, for the apex and every subdomain: the preload list is a property of the
# domain. The origins already send nosniff, so it stays off here.
resource "cloudflare_zone_setting" "hsts" {
  zone_id    = local.zone_id
  setting_id = "security_header"
  value = {
    strict_transport_security = {
      enabled            = true
      include_subdomains = true
      max_age            = 31536000
      nosniff            = false
      preload            = true
    }
  }
}

# Network Error Logging off for the zone: with it on, every response carries `nel` and `report-to`
# headers that make the visitor's browser report its network errors to a.nel.cloudflare.com, a
# third-party request no page of ours asked for.
resource "cloudflare_zone_setting" "nel" {
  zone_id    = local.zone_id
  setting_id = "nel"
  value = {
    enabled = false
  }
}

# The visitor's address as Cloudflare saw it, in `Forwarded` (RFC 7239): a header the visitor sent
# is overwritten, which `X-Forwarded-For` cannot be (Cloudflare appends to it and forbids setting
# it). Keycloak reads only this header (KC_PROXY_HEADERS=forwarded). RFC 7239 quotes an IPv6
# address in brackets, so the two families are two rules.
resource "cloudflare_ruleset" "client_address" {
  zone_id = local.zone_id
  name    = "client address"
  kind    = "zone"
  phase   = "http_request_late_transform"
  rules = [
    {
      description = "Forwarded carries the IPv4 address Cloudflare saw"
      action      = "rewrite"
      expression  = "ip.src in {0.0.0.0/0}"
      action_parameters = {
        headers = {
          "Forwarded" = {
            operation  = "set"
            expression = "concat(\"for=\", to_string(ip.src), \";proto=https\")"
          }
        }
      }
    },
    {
      description = "Forwarded carries the IPv6 address Cloudflare saw"
      action      = "rewrite"
      expression  = "ip.src in {::/0}"
      action_parameters = {
        headers = {
          "Forwarded" = {
            operation  = "set"
            expression = "concat(\"for=\\\"[\", to_string(ip.src), \"]\\\";proto=https\")"
          }
        }
      }
    },
  ]
}

# Paths the public may never reach, refused at Cloudflare's edge before the tunnel. Cloudflare
# normalizes the incoming URL first (https://developers.cloudflare.com/rules/normalization/how-it-works/),
# but leaves `%2F` encoded and only merges slashes with the zone's optional "Cloudflare" type, which
# this catalog does not control. So the rule decodes the path itself (`url_decode` with `r`, also
# `%252F`) and matches it with `wildcard` (https://developers.cloudflare.com/ruleset-engine/rules-language/operators/),
# which is case-insensitive and works on the Free plan; `matches` needs Business. Each `/` of the
# denied path becomes `/*`, so extra or encoded slashes, dot segments, a trailing slash and a longer
# tail are refused too: any decoded path with `auth/` followed later by `backchannel-logout`, for
# example `/oauth/backchannel-logout`, so the deny fails closed. The documentation of `http.host`
# (https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.host/)
# does not promise a port-free value, so a host matches as `<fqdn>` or `<fqdn>:<port>`.
# One rule per distinct path covers every host that lists it, so Free's 5 custom rules serve five
# paths, not five hosts.
locals {
  denied_paths = distinct(sort(flatten([for host in local.hosts : host.deny_public])))
  deny_rule_expressions = {
    for path in local.denied_paths : path => join(" ", [
      "(",
      join(" or ", [
        for fqdn in sort([for name, host in local.hosts : name if contains(host.deny_public, path)]) :
        "lower(http.host) eq \"${fqdn}\" or starts_with(lower(http.host), \"${fqdn}:\")"
      ]),
      ") and url_decode(http.request.uri.path, \"r\") wildcard \"/*${join("/*", split("/", trimprefix(path, "/")))}*\"",
    ])
  }
}

# A host's record waits for this ruleset (below), so a deny that fails publishes nothing. Without
# a denied path no ruleset exists: Cloudflare keeps one entry point per phase, which the zone may
# already hold (dashboard rules); then import it before the first apply (ID
# `zones/<zone_id>/<ruleset_id>`). The import does not keep those rules: this resource's rules come
# whole from the catalog, so the plan shows each existing rule as removed, and the operator stops
# there until it is written into the catalog or removed on purpose.
resource "cloudflare_ruleset" "deny_public" {
  count   = length(local.denied_paths) > 0 ? 1 : 0
  zone_id = local.zone_id
  name    = "public deny"
  kind    = "zone"
  phase   = "http_request_firewall_custom"
  rules = [
    for path in local.denied_paths : {
      description = "${path} is never reachable from outside"
      action      = "block"
      expression  = local.deny_rule_expressions[path]
    }
  ]
}

# The catalog's redirected names (cloudflare.redirect) answer 302 at Cloudflare's edge and never
# reach the tunnel. Single Redirects run in the phase http_request_dynamic_redirect, in order, and a
# redirect ends the evaluation (https://developers.cloudflare.com/rules/url-forwarding/, which also
# lists the Free plan's 10 single redirects),
# so one rule per served page comes first and the last rule takes the rest.
# The target is a static URL (`from_value.target_url.value`), so the path and, with preserve_query_string off, the query of
# the request are dropped
# (https://developers.cloudflare.com/rules/url-forwarding/single-redirects/create-api/). A host
# matches as `<fqdn>` or `<fqdn>:<port>`, as in the public deny. With
# `redirect.serve` the apex answers its pages (exactly, as written) and everything under its files
# prefix from the tunnel: the rule of a page sends every other form of it (another case, a trailing
# slash, www) to the apex's exact path, and the last rule leaves the apex's served paths out. Only
# https is redirected (`ssl`): `http://` first goes to https on the same host (Always Use HTTPS), as the
# HSTS preload requires.
# A record waits for this ruleset, as for the deny. Without `cloudflare.redirect` no ruleset
# exists; if the zone already holds the entry point of this phase, import it before the first apply
# (ID `zones/<zone_id>/<ruleset_id>`): its rules are not kept, the plan shows each as removed.
locals {
  redirect_host_expression = join(" or ", [
    for fqdn in sort(local.redirect_fqdns) :
    "lower(http.host) eq \"${fqdn}\" or starts_with(lower(http.host), \"${fqdn}:\")"
  ])
  apex_host_expression = "lower(http.host) eq \"${local.fleet.cloudflare.zone}\" or starts_with(lower(http.host), \"${local.fleet.cloudflare.zone}:\")"
  served_pages         = try(local.redirect.serve.pages, [])
  served_expression = join(" or ", concat(
    length(local.served_pages) == 0 ? [] : ["http.request.uri.path in {${join(" ", [for page in local.served_pages : "\"${page}\""])}}"],
    try(["starts_with(http.request.uri.path, \"${local.redirect.serve.files}\")"], [])
  ))
  redirect_rules = local.redirect == null ? [] : concat(
    [
      for page in local.served_pages : {
        description = "${page} is served at ${local.fleet.cloudflare.zone}"
        expression  = "ssl and ( ${local.redirect_host_expression} ) and lower(http.request.uri.path) in {\"${page}\" \"${page}/\"} and not ( ( ${local.apex_host_expression} ) and http.request.uri.path eq \"${page}\" )"
        target_url  = "https://${local.fleet.cloudflare.zone}${page}"
      }
    ],
    [{
      description = "everything else goes to ${local.redirect.target}"
      expression  = "ssl and ( ${local.redirect_host_expression} )${local.served_expression == "" ? "" : " and not ( ( ${local.apex_host_expression} ) and ( ${local.served_expression} ) )"}"
      target_url  = local.redirect.target
    }]
  )
}

resource "cloudflare_ruleset" "apex_redirect" {
  count   = length(local.redirect_rules) > 0 ? 1 : 0
  zone_id = local.zone_id
  name    = "apex redirect"
  kind    = "zone"
  phase   = "http_request_dynamic_redirect"
  rules = [
    for rule in local.redirect_rules : {
      description = rule.description
      action      = "redirect"
      expression  = rule.expression
      action_parameters = {
        from_value = {
          status_code           = 302
          preserve_query_string = false
          target_url            = { value = rule.target_url }
        }
      }
    }
  ]
}

import {
  for_each = local.record_ids_to_import
  to       = cloudflare_dns_record.host[each.key]
  id       = each.value
}

import {
  for_each = local.app_ids_to_import
  to       = cloudflare_zero_trust_access_application.host[each.key]
  id       = each.value
}
