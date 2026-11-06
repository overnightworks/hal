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
  catalog_file = "tests/fixtures/hosts-plain.yaml"
  tunnel_id    = "tunnel-id"
}

run "t1_the_plain_catalog_gets_one_line_per_host_and_the_404_rule_last" {
  command = plan

  assert {
    condition = (
      tolist([for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.hostname])
      == tolist(["edge-fixture.invalid", "www.edge-fixture.invalid", null])
    )
    error_message = "the lines are not the apex, www and then a rule without a hostname"
  }

  assert {
    condition = (
      [for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.service]
      == ["http://127.0.0.1:8081", "http://127.0.0.1:8081", "http_status:404"]
    )
    error_message = "the hosts do not point to their targets, or the 404 rule is not last"
  }
}

run "t5_a_disabled_entry_gets_no_line" {
  command = plan

  assert {
    condition = !contains(
      [for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.hostname],
      "gone.edge-fixture.invalid"
    )
    error_message = "the disabled entry's host got a tunnel line"
  }
}

run "t2_the_auth_line_is_the_bare_pair" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/tunnel-auth.yaml"
  }

  assert {
    condition = [
      for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress :
      "${rule.service} ${rule.path == null} ${rule.origin_request == null}"
      if rule.hostname == "auth.edge-fixture.invalid"
    ] == ["http://127.0.0.1:8081 true true"]
    error_message = "auth is not exactly one bare hostname and service line to 127.0.0.1:8081"
  }
}

run "t11_the_lines_follow_the_lexical_order_of_the_hostnames" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/tunnel-auth.yaml"
  }

  assert {
    condition = (
      tolist([for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.hostname])
      == tolist(["auth.edge-fixture.invalid", "edge-fixture.invalid", "www.edge-fixture.invalid", null])
    )
    error_message = "the hostnames are not auth, the apex, www and then the 404 rule"
  }
}

# T3, T4, T12 and T14 hold for every catalog: one run per fixture, the same four asserts.
run "t3_t4_t12_t14_the_plain_catalog_writes_only_bare_cloudflare_managed_lines" {
  command = plan

  assert {
    condition = alltrue([
      for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress :
      rule.origin_request == null && rule.path == null
    ])
    error_message = "a line carries origin_request or path"
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.source == "cloudflare" && cloudflare_zero_trust_tunnel_cloudflared_config.this.config != null
    error_message = "the configuration is not Cloudflare's or has no config"
  }

  assert {
    condition = alltrue([
      for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress :
      rule.service == "http_status:404" || contains([for host in local.hosts : host.target], rule.service)
    ])
    error_message = "a line serves something no declared host targets"
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.config.origin_request == null
    error_message = "a config-level origin_request would make public hosts inherit it"
  }
}

run "t3_t4_t12_t14_the_auth_catalog_writes_only_bare_cloudflare_managed_lines" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/tunnel-auth.yaml"
  }

  assert {
    condition = alltrue([
      for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress :
      rule.origin_request == null && rule.path == null
    ])
    error_message = "a line carries origin_request or path"
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.source == "cloudflare" && cloudflare_zero_trust_tunnel_cloudflared_config.this.config != null
    error_message = "the configuration is not Cloudflare's or has no config"
  }

  assert {
    condition = alltrue([
      for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress :
      rule.service == "http_status:404" || contains([for host in local.hosts : host.target], rule.service)
    ])
    error_message = "a line serves something no declared host targets"
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.config.origin_request == null
    error_message = "a config-level origin_request would make public hosts inherit it"
  }
}

run "t3_t4_t12_t14_the_empty_catalog_writes_only_bare_cloudflare_managed_lines" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/empty.yaml"
  }

  assert {
    condition = alltrue([
      for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress :
      rule.origin_request == null && rule.path == null
    ])
    error_message = "a line carries origin_request or path"
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.source == "cloudflare" && cloudflare_zero_trust_tunnel_cloudflared_config.this.config != null
    error_message = "the configuration is not Cloudflare's or has no config"
  }

  assert {
    condition = alltrue([
      for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress :
      rule.service == "http_status:404" || contains([for host in local.hosts : host.target], rule.service)
    ])
    error_message = "a line serves something no declared host targets"
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.config.origin_request == null
    error_message = "a config-level origin_request would make public hosts inherit it"
  }
}

run "t8_a_cloudflare_managed_tunnel_imports_its_configuration" {
  command = plan

  plan_options {
    mode = refresh-only
  }

  override_data {
    target = data.cloudflare_zero_trust_tunnel_cloudflared.this
    values = { id = "tunnel-id", config_src = "cloudflare" }
  }

  assert {
    condition     = local.tunnel_config_ids_to_import == tomap({ tunnel = "account-id/tunnel-id" })
    error_message = "a Cloudflare-managed tunnel's configuration is not imported by its account and tunnel id"
  }
}

run "t8_a_tunnel_that_is_not_cloudflare_managed_imports_nothing" {
  command = plan

  assert {
    condition     = length(local.tunnel_config_ids_to_import) == 0
    error_message = "a tunnel that is not Cloudflare-managed imports its remote copy"
  }
}

run "t6_apply_the_catalog_with_auth" {
  command = apply

  variables {
    catalog_file = "tests/fixtures/tunnel-auth.yaml"
  }
}

run "t6_a_removed_host_leaves_the_lines_in_place" {
  command = plan

  assert {
    condition = (
      tolist([for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.hostname])
      == tolist(["edge-fixture.invalid", "www.edge-fixture.invalid", null])
    )
    error_message = "the configuration is not planned, or still has the removed auth line"
  }
}

run "t9_apply_the_plain_catalog" {
  command = apply
}

run "t9_a_changed_tunnel_id_moves_the_configuration_to_it" {
  command = plan

  override_data {
    target = data.cloudflare_zero_trust_tunnel_cloudflared.this
    values = { id = "new-tunnel-id" }
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.tunnel_id == "new-tunnel-id"
    error_message = "the configuration does not follow the changed tunnel"
  }
}

run "t13_removing_the_last_host_leaves_only_the_404_rule" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/empty.yaml"
  }

  assert {
    condition = (
      [for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.service]
      == ["http_status:404"]
    )
    error_message = "the configuration is not planned with the 404 rule alone"
  }
}
