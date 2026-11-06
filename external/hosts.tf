# The hosts of the enabled catalog entries, keyed by FQDN. src/hal/stack/catalog.py validates the shape
# before tofu starts (`hal apply` refuses an invalid catalog), so this reads it
# as it stands; `try` covers only the optional keys.
locals {
  default_host_target = "http://127.0.0.1:8081"

  hosts = merge([
    for service, entry in try(local.fleet.services, {}) : {
      for host in try(entry.hosts, []) :
      (host.name == "@" ? local.fleet.cloudflare.zone : "${host.name}.${local.fleet.cloudflare.zone}") => {
        service  = service
        exposure = host.exposure
        reason   = try(host.reason, null)
        ready    = try(host.ready, null)
        target   = try(host.target, local.default_host_target)

        deny_public = try(host.deny_public, [])
        tunnel      = try(host.tunnel, null)
      }
    } if try(entry.run.enabled, true)
  ]...)
}
