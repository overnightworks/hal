# The tunnel's ingress, written from the catalog (D6: Cloudflare manages the tunnel, OpenTofu writes
# its lines through the API). The configuration is one object owned whole by the catalog: a line
# added anywhere else is drift, and apply removes it after the plan and `yes`.
locals {
  # keys() is lexical, which fixes the order of the lines. A host another tunnel serves has its
  # line in that tunnel's ingress, which its owner writes.
  host_ingress_rules = [
    for fqdn in keys(local.hosts) : { hostname = fqdn, service = local.hosts[fqdn].target }
    if local.hosts[fqdn].tunnel == null
  ]
  deny_by_default_rule = { service = "http_status:404" }

  wildcard_fqdn = "*.${local.fleet.cloudflare.zone}"

  # A remotely managed tunnel's configuration is adopted, so the diff shows its foreign lines as removed.
  # While the tunnel is still local, its remote copy does not serve and is not imported.
  tunnel_config_ids_to_import = (
    data.cloudflare_zero_trust_tunnel_cloudflared.this.config_src == "cloudflare"
    ? { tunnel = "${local.account_id}/${local.tunnel_id}" }
    : {}
  )
}

# Without a count: the configuration outlives the last host, so removing it is an in-place update
# that leaves the 404 rule alone, never a forgotten configuration with its old lines still live.
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "this" {
  account_id = local.account_id
  tunnel_id  = local.tunnel_id
  source     = "cloudflare"
  config = {
    ingress = concat(local.host_ingress_rules, [local.deny_by_default_rule])
  }

  # Rule 8: a line goes live only after its record, which itself waits for the Access apps.
  depends_on = [cloudflare_dns_record.host]

  lifecycle {
    # The lexical order would put the wildcard ahead of every host; X8b adds it with Access and deletes this.
    precondition {
      condition     = !contains(keys(local.hosts), local.wildcard_fqdn)
      error_message = "A ${local.wildcard_fqdn} host has no tunnel line until X8b; its lexical place would shadow every other host."
    }

    # Such a host would have no line in hal's ingress and answer its 404.
    precondition {
      condition     = !contains(values(local.named_tunnel_ids), local.tunnel_id)
      error_message = "A host names a tunnel whose id ${local.tunnel_id} is hal's own; it would get no line in hal's ingress."
    }
  }
}

import {
  for_each = local.tunnel_config_ids_to_import
  to       = cloudflare_zero_trust_tunnel_cloudflared_config.this
  id       = each.value
}
