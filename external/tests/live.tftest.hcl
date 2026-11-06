mock_provider "cloudflare" {
  mock_data "cloudflare_zone" {
    defaults = {
      id      = "0123456789abcdef0123456789abcdef"
      account = { id = "account-id", name = "fixture account" }
    }
  }

  mock_data "cloudflare_zero_trust_tunnel_cloudflared" {
    defaults = { id = "tunnel-id" }
  }

  mock_data "cloudflare_zero_trust_access_groups" {
    defaults = {
      result = [{ id = "group-id", name = "operator", is_default = [], include = [], exclude = [], require = [] }]
    }
  }
}

variables {
  tunnel_id = "tunnel-id"
}

# The live catalog, rendered with the mocked provider: its apex redirect stays within the 10 single
# redirects Cloudflare's Free plan allows (https://developers.cloudflare.com/rules/url-forwarding/).
run "the_live_catalogs_apex_redirect_stays_within_the_free_plans_limit" {
  command = plan

  variables {
    catalog_file = "../fleet.yaml"
  }

  assert {
    condition     = length(cloudflare_ruleset.apex_redirect[0].rules) <= 10
    error_message = "the apex redirect has more rules than the 10 single redirects of Cloudflare's Free plan"
  }
}

# The live catalog's denied paths reach the rendered deny ruleset: every enabled host that lists a
# path is named by a blocking rule for that path.
run "every_live_denied_path_reaches_a_blocking_rule_for_its_host" {
  command = plan

  variables {
    catalog_file = "../fleet.yaml"
  }

  assert {
    condition = alltrue(flatten([
      for service, entry in yamldecode(file("../fleet.yaml")).services : [
        for host in try(entry.hosts, []) : [
          for path in try(host.deny_public, []) : anytrue([
            for rule in cloudflare_ruleset.deny_public[0].rules :
            rule.action == "block"
            && startswith(rule.description, "${path} ")
            && strcontains(rule.expression, "\"${host.name == "@" ? yamldecode(file("../fleet.yaml")).cloudflare.zone : "${host.name}.${yamldecode(file("../fleet.yaml")).cloudflare.zone}"}\"")
          ])
        ]
      ] if try(entry.run.enabled, true)
    ]))
    error_message = "a path the live catalog denies has no blocking rule for its host in the rendered ruleset"
  }
}
