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

run "c1_public_hosts_get_proxied_cnames_to_the_tunnel_and_no_app" {
  command = plan

  assert {
    condition = alltrue([
      for fqdn in ["edge-fixture.invalid", "www.edge-fixture.invalid"] :
      cloudflare_dns_record.host[fqdn].name == fqdn
      && cloudflare_dns_record.host[fqdn].type == "CNAME"
      && cloudflare_dns_record.host[fqdn].content == "tunnel-id.cfargotunnel.com"
      && cloudflare_dns_record.host[fqdn].proxied
      && cloudflare_dns_record.host[fqdn].ttl == 1
      && cloudflare_dns_record.host[fqdn].zone_id == "0123456789abcdef0123456789abcdef"
    ])
    error_message = "the apex and www are not proxied CNAMEs to the tunnel with TTL 1"
  }

  assert {
    condition     = length(cloudflare_dns_record.host) == 2
    error_message = "a disabled entry's host got a record"
  }

  assert {
    condition     = length(cloudflare_zero_trust_access_application.host) == 0 && length(cloudflare_zero_trust_access_policy.bypass) == 0 && length(cloudflare_zero_trust_access_policy.allow_operator) == 0
    error_message = "public hosts got an app or a policy"
  }
}

# A second tunnel in the account is never asked for: the lookup names hal's id among the live
# tunnels, and the mock answers as the provider does for that filter, with exactly that tunnel.
run "c13_records_and_ingress_follow_the_live_tunnel_with_hals_id" {
  command = plan

  variables {
    tunnel_id = "hal-tunnel-id"
  }

  override_data {
    target = data.cloudflare_zero_trust_tunnel_cloudflared.this
    values = { id = "hal-tunnel-id" }
  }

  assert {
    condition = (
      data.cloudflare_zero_trust_tunnel_cloudflared.this.filter.uuid == "hal-tunnel-id"
      && data.cloudflare_zero_trust_tunnel_cloudflared.this.filter.is_deleted == false
    )
    error_message = "the tunnel is not looked up as the live one with hal's id"
  }

  assert {
    condition = alltrue([
      for record in cloudflare_dns_record.host : record.content == "hal-tunnel-id.cfargotunnel.com"
    ])
    error_message = "a record does not point at hal's tunnel"
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.this.tunnel_id == "hal-tunnel-id"
    error_message = "the ingress is not planned on hal's tunnel"
  }
}

run "c18_the_zone_sends_hsts_with_preload_for_every_subdomain" {
  command = plan

  assert {
    condition = (
      cloudflare_zone_setting.hsts.zone_id == "0123456789abcdef0123456789abcdef"
      && cloudflare_zone_setting.hsts.setting_id == "security_header"
      && cloudflare_zone_setting.hsts.value.strict_transport_security == {
        enabled            = true
        include_subdomains = true
        max_age            = 31536000
        nosniff            = false
        preload            = true
      }
    )
    error_message = "the zone's HSTS is not max-age=31536000; includeSubDomains; preload without nosniff"
  }
}

run "c22_the_zone_turns_network_error_logging_off" {
  command = plan

  assert {
    condition = (
      cloudflare_zone_setting.nel.zone_id == "0123456789abcdef0123456789abcdef"
      && cloudflare_zone_setting.nel.setting_id == "nel"
      && cloudflare_zone_setting.nel.value == { enabled = false }
    )
    error_message = "the zone's Network Error Logging is not switched off"
  }
}

run "c19_the_zone_overwrites_forwarded_with_the_address_cloudflare_saw" {
  command = plan

  assert {
    condition = (
      cloudflare_ruleset.client_address.zone_id == "0123456789abcdef0123456789abcdef"
      && cloudflare_ruleset.client_address.kind == "zone"
      && cloudflare_ruleset.client_address.phase == "http_request_late_transform"
    )
    error_message = "the client address ruleset is not the zone's late request transform entry point"
  }

  assert {
    condition = [
      for rule in cloudflare_ruleset.client_address.rules : [
        rule.action,
        rule.expression,
        rule.action_parameters.headers["Forwarded"].operation,
        rule.action_parameters.headers["Forwarded"].expression,
      ]
      ] == [
      ["rewrite", "ip.src in {0.0.0.0/0}", "set", "concat(\"for=\", to_string(ip.src), \";proto=https\")"],
      ["rewrite", "ip.src in {::/0}", "set", "concat(\"for=\\\"[\", to_string(ip.src), \"]\\\";proto=https\")"],
    ]
    error_message = "Forwarded is not set from ip.src, bare for IPv4 and quoted in brackets for IPv6"
  }
}

run "c3_a_bypass_host_gets_a_record_an_app_and_the_bypass_policy" {
  command = plan

  override_resource {
    target = cloudflare_zero_trust_access_policy.bypass[0]
    values = { id = "bypass-policy-id" }
  }

  variables {
    catalog_file = "tests/fixtures/cloudflare-bypass.yaml"
  }

  assert {
    condition     = length(cloudflare_dns_record.host) == 1 && length(cloudflare_zero_trust_access_application.host) == 1 && length(cloudflare_zero_trust_access_policy.bypass) == 1
    error_message = "expected one record, one app and one Bypass policy"
  }

  assert {
    condition     = cloudflare_zero_trust_access_policy.bypass[0].decision == "bypass" && length(cloudflare_zero_trust_access_policy.allow_operator) == 0
    error_message = "the policy is not the Bypass policy, or an allow policy exists too"
  }

  assert {
    condition     = cloudflare_zero_trust_access_application.host["hopin.edge-fixture.invalid"].domain == "hopin.edge-fixture.invalid"
    error_message = "the app is not on the host's FQDN"
  }

  assert {
    condition     = [for destination in cloudflare_zero_trust_access_application.host["hopin.edge-fixture.invalid"].destinations : "${destination.type} ${destination.uri}"] == ["public hopin.edge-fixture.invalid"]
    error_message = "the app does not name the host's FQDN as its public destination"
  }

  assert {
    condition = (
      [for policy in cloudflare_zero_trust_access_application.host["hopin.edge-fixture.invalid"].policies : policy.id] == ["bypass-policy-id"]
      && [for entry in cloudflare_zero_trust_access_policy.bypass[0].include : entry.everyone != null] == [true]
    )
    error_message = "the app does not attach the Bypass policy, or that policy does not include everyone"
  }
}

run "c4_a_host_of_a_disabled_entry_gets_nothing" {
  command = plan

  assert {
    condition     = !contains(keys(cloudflare_dns_record.host), "gone.edge-fixture.invalid")
    error_message = "the disabled entry's host got a record"
  }
}

run "c5_a_protected_wildcard_gets_an_allow_group_app" {
  command = plan

  override_resource {
    target = cloudflare_zero_trust_access_policy.allow_operator[0]
    values = { id = "allow-policy-id" }
  }

  variables {
    catalog_file = "tests/fixtures/cloudflare-protected.yaml"
  }

  # The tunnel line for the wildcard waits for X8b (T10); X8b deletes this entry with the tripwire.
  expect_failures = [cloudflare_zero_trust_tunnel_cloudflared_config.this]

  assert {
    condition     = cloudflare_zero_trust_access_policy.allow_operator[0].decision == "allow" && [for entry in cloudflare_zero_trust_access_policy.allow_operator[0].include : entry.group.id] == ["group-id"]
    error_message = "the protected host's policy does not allow the operator group"
  }

  assert {
    condition     = length(cloudflare_zero_trust_access_application.host) == 1 && length(cloudflare_zero_trust_access_policy.bypass) == 0
    error_message = "expected one app for the wildcard and no Bypass policy"
  }

  assert {
    condition     = [for policy in cloudflare_zero_trust_access_application.host["*.edge-fixture.invalid"].policies : policy.id] == ["allow-policy-id"]
    error_message = "the wildcard app does not attach the allow-group policy"
  }

  assert {
    condition     = [for destination in cloudflare_zero_trust_access_application.host["*.edge-fixture.invalid"].destinations : "${destination.type} ${destination.uri}"] == ["public *.edge-fixture.invalid"]
    error_message = "the wildcard app does not name the wildcard FQDN as its public destination"
  }
}

run "c5_a_protected_host_without_the_operator_group_fails" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/cloudflare-protected.yaml"
  }

  override_data {
    target = data.cloudflare_zero_trust_access_groups.operator[0]
    values = { result = [] }
  }

  expect_failures = [cloudflare_zero_trust_access_policy.allow_operator]
}

run "c5_two_operator_groups_fail_a_protected_host" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/cloudflare-protected.yaml"
  }

  override_data {
    target = data.cloudflare_zero_trust_access_groups.operator[0]
    values = {
      result = [
        { id = "first-group", name = "operator", is_default = [], include = [], exclude = [], require = [] },
        { id = "second-group", name = "operator", is_default = [], include = [], exclude = [], require = [] },
      ]
    }
  }

  expect_failures = [cloudflare_zero_trust_access_policy.allow_operator]
}

run "c7_a_live_a_record_on_the_apex_fails_the_plan" {
  command = plan

  override_data {
    target = data.cloudflare_dns_records.host["edge-fixture.invalid"]
    values = {
      result = [{ id = "live-a", type = "A", comment = null, comment_modified_on = null, content = null, created_on = null, data = null, meta = null, modified_on = null, name = null, priority = null, private_routing = null, proxiable = null, proxied = null, settings = null, tags = null, tags_modified_on = null, ttl = null }]
    }
  }

  expect_failures = [data.cloudflare_dns_records.host]
}

run "c7_a_live_aaaa_record_on_the_apex_fails_the_plan" {
  command = plan

  override_data {
    target = data.cloudflare_dns_records.host["edge-fixture.invalid"]
    values = {
      result = [{ id = "live-aaaa", type = "AAAA", comment = null, comment_modified_on = null, content = null, created_on = null, data = null, meta = null, modified_on = null, name = null, priority = null, private_routing = null, proxiable = null, proxied = null, settings = null, tags = null, tags_modified_on = null, ttl = null }]
    }
  }

  expect_failures = [data.cloudflare_dns_records.host]
}

run "c7_two_live_cnames_on_www_fail_the_plan" {
  command = plan

  override_data {
    target = data.cloudflare_dns_records.host["www.edge-fixture.invalid"]
    values = {
      result = [
        { id = "first", type = "CNAME", comment = null, comment_modified_on = null, content = null, created_on = null, data = null, meta = null, modified_on = null, name = null, priority = null, private_routing = null, proxiable = null, proxied = null, settings = null, tags = null, tags_modified_on = null, ttl = null },
        { id = "second", type = "CNAME", comment = null, comment_modified_on = null, content = null, created_on = null, data = null, meta = null, modified_on = null, name = null, priority = null, private_routing = null, proxiable = null, proxied = null, settings = null, tags = null, tags_modified_on = null, ttl = null },
      ]
    }
  }

  expect_failures = [data.cloudflare_dns_records.host]
}

run "c9_mx_and_txt_records_at_the_apex_are_ignored" {
  command = plan

  override_data {
    target = data.cloudflare_dns_records.host["edge-fixture.invalid"]
    values = {
      result = [
        { id = "mx", type = "MX", comment = null, comment_modified_on = null, content = null, created_on = null, data = null, meta = null, modified_on = null, name = null, priority = null, private_routing = null, proxiable = null, proxied = null, settings = null, tags = null, tags_modified_on = null, ttl = null },
        { id = "txt", type = "TXT", comment = null, comment_modified_on = null, content = null, created_on = null, data = null, meta = null, modified_on = null, name = null, priority = null, private_routing = null, proxiable = null, proxied = null, settings = null, tags = null, tags_modified_on = null, ttl = null },
      ]
    }
  }

  assert {
    condition     = length(local.record_ids_to_import) == 0 && contains(keys(cloudflare_dns_record.host), "edge-fixture.invalid")
    error_message = "other record types were imported, or the apex record is not planned"
  }
}

run "c11_two_apps_for_a_bypass_host_fail_the_plan" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/cloudflare-bypass.yaml"
  }

  override_data {
    target = data.cloudflare_zero_trust_access_applications.host["hopin.edge-fixture.invalid"]
    values = {
      result = [
        { id = "first", allow_authenticate_via_warp = null, allow_iframe = null, allowed_idps = null, app_launcher_logo_url = null, app_launcher_visible = null, aud = null, auto_redirect_to_identity = null, bg_color = null, cors_headers = null, custom_deny_message = null, custom_deny_url = null, custom_non_identity_deny_url = null, custom_pages = null, destinations = null, domain = null, enable_binding_cookie = null, footer_links = null, header_bg_color = null, http_only_cookie_attribute = null, landing_page_design = null, logo_url = null, mfa_config = null, name = null, options_preflight_bypass = null, path_cookie_attribute = null, policies = null, read_service_tokens_from_header = null, saas_app = null, same_site_cookie_attribute = null, scim_config = null, self_hosted_domains = null, service_auth_401_redirect = null, session_duration = null, skip_app_launcher_login_page = null, skip_interstitial = null, tags = null, target_criteria = null, type = null },
        { id = "second", allow_authenticate_via_warp = null, allow_iframe = null, allowed_idps = null, app_launcher_logo_url = null, app_launcher_visible = null, aud = null, auto_redirect_to_identity = null, bg_color = null, cors_headers = null, custom_deny_message = null, custom_deny_url = null, custom_non_identity_deny_url = null, custom_pages = null, destinations = null, domain = null, enable_binding_cookie = null, footer_links = null, header_bg_color = null, http_only_cookie_attribute = null, landing_page_design = null, logo_url = null, mfa_config = null, name = null, options_preflight_bypass = null, path_cookie_attribute = null, policies = null, read_service_tokens_from_header = null, saas_app = null, same_site_cookie_attribute = null, scim_config = null, self_hosted_domains = null, service_auth_401_redirect = null, session_duration = null, skip_app_launcher_login_page = null, skip_interstitial = null, tags = null, target_criteria = null, type = null },
      ]
    }
  }

  expect_failures = [data.cloudflare_zero_trust_access_applications.host]
}

run "c1_one_live_cname_on_www_is_imported" {
  command = plan

  plan_options {
    mode = refresh-only
  }

  override_data {
    target = data.cloudflare_dns_records.host["www.edge-fixture.invalid"]
    values = {
      result = [{ id = "cname-id", type = "CNAME", comment = null, comment_modified_on = null, content = null, created_on = null, data = null, meta = null, modified_on = null, name = null, priority = null, private_routing = null, proxiable = null, proxied = null, settings = null, tags = null, tags_modified_on = null, ttl = null }]
    }
  }

  assert {
    condition     = local.record_ids_to_import == { "www.edge-fixture.invalid" = "0123456789abcdef0123456789abcdef/cname-id" }
    error_message = "the live CNAME on www is not imported by its zone and record id"
  }
}

run "c10_a_live_cname_with_other_content_is_imported_without_failure" {
  command = plan

  plan_options {
    mode = refresh-only
  }

  override_data {
    target = data.cloudflare_dns_records.host["www.edge-fixture.invalid"]
    values = {
      result = [{ id = "cname-id", type = "CNAME", comment = null, comment_modified_on = null, content = "elsewhere.invalid", created_on = null, data = null, meta = null, modified_on = null, name = null, priority = null, private_routing = null, proxiable = null, proxied = false, settings = null, tags = null, tags_modified_on = null, ttl = 300 }]
    }
  }

  assert {
    condition     = local.record_ids_to_import == { "www.edge-fixture.invalid" = "0123456789abcdef0123456789abcdef/cname-id" }
    error_message = "a CNAME with other content was not adopted, or it failed the plan"
  }
}

run "c11_one_app_for_a_bypass_host_is_imported" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/cloudflare-bypass.yaml"
  }

  plan_options {
    mode = refresh-only
  }

  override_data {
    target = data.cloudflare_zero_trust_access_applications.host["hopin.edge-fixture.invalid"]
    values = {
      result = [{ id = "app-id", allow_authenticate_via_warp = null, allow_iframe = null, allowed_idps = null, app_launcher_logo_url = null, app_launcher_visible = null, aud = null, auto_redirect_to_identity = null, bg_color = null, cors_headers = null, custom_deny_message = null, custom_deny_url = null, custom_non_identity_deny_url = null, custom_pages = null, destinations = null, domain = "hopin.edge-fixture.invalid", enable_binding_cookie = null, footer_links = null, header_bg_color = null, http_only_cookie_attribute = null, landing_page_design = null, logo_url = null, mfa_config = null, name = null, options_preflight_bypass = null, path_cookie_attribute = null, policies = null, read_service_tokens_from_header = null, saas_app = null, same_site_cookie_attribute = null, scim_config = null, self_hosted_domains = null, service_auth_401_redirect = null, session_duration = null, skip_app_launcher_login_page = null, skip_interstitial = null, tags = null, target_criteria = null, type = null }]
    }
  }

  assert {
    condition     = local.app_ids_to_import == { "hopin.edge-fixture.invalid" = "accounts/account-id/app-id" }
    error_message = "the live app is not imported by its account and app id"
  }
}

run "c11_no_app_for_a_bypass_host_is_imported_so_one_is_created" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/cloudflare-bypass.yaml"
  }

  assert {
    condition     = length(local.app_ids_to_import) == 0 && length(cloudflare_zero_trust_access_application.host) == 1
    error_message = "the missing app should be planned, not imported"
  }
}

run "t7_without_hosts_only_the_zone_and_the_tunnel_are_looked_up" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/empty.yaml"
  }

  assert {
    condition = alltrue([
      length(data.cloudflare_dns_records.host) == 0,
      length(data.cloudflare_zero_trust_access_applications.host) == 0,
      length(data.cloudflare_zero_trust_access_groups.operator) == 0,
    ])
    error_message = "a per-host lookup was read although no host is declared"
  }

  assert {
    condition     = data.cloudflare_zone.this.id == "0123456789abcdef0123456789abcdef" && data.cloudflare_zero_trust_tunnel_cloudflared.this.id == "tunnel-id"
    error_message = "the zone and the tunnel are not looked up without a host"
  }

  assert {
    condition     = [for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.service] == ["http_status:404"]
    error_message = "the tunnel configuration is not planned with the 404 rule alone"
  }

  assert {
    condition = alltrue([
      length(cloudflare_zero_trust_access_application.host) == 0,
      length(cloudflare_zero_trust_access_policy.bypass) == 0,
      length(cloudflare_zero_trust_access_policy.allow_operator) == 0,
    ])
    error_message = "an Access resource is planned although no host is declared"
  }
}

run "r7_apply_the_public_hosts" {
  command = apply
}

run "r7_a_changed_tunnel_updates_every_record_content" {
  command = plan

  override_data {
    target = data.cloudflare_zero_trust_tunnel_cloudflared.this
    values = { id = "new-tunnel-id" }
  }

  assert {
    condition = alltrue([
      for record in cloudflare_dns_record.host : record.content == "new-tunnel-id.cfargotunnel.com"
    ])
    error_message = "a record does not follow the changed tunnel"
  }
}

run "c17_apply_a_bypass_host" {
  command = apply

  variables {
    catalog_file = "tests/fixtures/cloudflare-bypass.yaml"
  }

  assert {
    condition     = length(cloudflare_dns_record.host) == 1 && length(cloudflare_zero_trust_access_application.host) == 1
    error_message = "the host was not applied"
  }
}

run "c17_the_removed_host_leaves_the_plan" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/empty.yaml"
  }

  assert {
    condition     = length(cloudflare_dns_record.host) == 0 && length(cloudflare_zero_trust_access_application.host) == 0 && length(cloudflare_zero_trust_access_policy.bypass) == 0
    error_message = "the removed host's objects are still planned"
  }
}

run "c20_one_rule_per_denied_path_covers_every_host_listing_it" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/cloudflare-deny.yaml"
  }

  assert {
    condition = (
      cloudflare_ruleset.deny_public[0].zone_id == "0123456789abcdef0123456789abcdef"
      && cloudflare_ruleset.deny_public[0].kind == "zone"
      && cloudflare_ruleset.deny_public[0].phase == "http_request_firewall_custom"
    )
    error_message = "the deny is not the zone's custom rules entry point"
  }

  assert {
    condition = [for rule in cloudflare_ruleset.deny_public[0].rules : [rule.action, rule.expression]] == [
      [
        "block",
        "( lower(http.host) eq \"guarded.edge-fixture.invalid\" or starts_with(lower(http.host), \"guarded.edge-fixture.invalid:\") or lower(http.host) eq \"twin.edge-fixture.invalid\" or starts_with(lower(http.host), \"twin.edge-fixture.invalid:\") ) and url_decode(http.request.uri.path, \"r\") wildcard \"/*auth/*backchannel-logout*\"",
      ],
      [
        "block",
        "( lower(http.host) eq \"guarded.edge-fixture.invalid\" or starts_with(lower(http.host), \"guarded.edge-fixture.invalid:\") ) and url_decode(http.request.uri.path, \"r\") wildcard \"/*hook*\"",
      ],
    ]
    error_message = "the rendered rules are not one block rule per path, testing each listing host with and without a port and decoding the path"
  }
}

run "c21_a_catalog_without_a_deny_plans_no_ruleset" {
  command = plan

  assert {
    condition     = length(cloudflare_ruleset.deny_public) == 0
    error_message = "a ruleset is planned though no host denies a path"
  }
}

run "x11b_the_redirected_names_get_records_the_apex_a_tunnel_line_www_none_and_one_redirect_ruleset" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/cloudflare-redirect.yaml"
  }

  assert {
    condition = (
      toset(keys(cloudflare_dns_record.host)) == toset(["app.edge-fixture.invalid", "edge-fixture.invalid", "www.edge-fixture.invalid"])
      && alltrue([for record in cloudflare_dns_record.host : record.proxied])
      && [for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.hostname == null ? "" : rule.hostname] == ["app.edge-fixture.invalid", "edge-fixture.invalid", ""]
    )
    error_message = "the app, the apex and www do not have proxied records, or the tunnel lines are not the app, the apex and the 404 (none for www)"
  }

  assert {
    condition = (
      cloudflare_ruleset.apex_redirect[0].phase == "http_request_dynamic_redirect"
      && cloudflare_ruleset.apex_redirect[0].kind == "zone"
      && [for rule in cloudflare_ruleset.apex_redirect[0].rules : [rule.action, rule.expression, rule.action_parameters.from_value.target_url.value, rule.action_parameters.from_value.status_code, rule.action_parameters.from_value.preserve_query_string]] == [
        [
          "redirect",
          "ssl and ( lower(http.host) eq \"edge-fixture.invalid\" or starts_with(lower(http.host), \"edge-fixture.invalid:\") or lower(http.host) eq \"www.edge-fixture.invalid\" or starts_with(lower(http.host), \"www.edge-fixture.invalid:\") ) and lower(http.request.uri.path) in {\"/terms\" \"/terms/\"} and not ( ( lower(http.host) eq \"edge-fixture.invalid\" or starts_with(lower(http.host), \"edge-fixture.invalid:\") ) and http.request.uri.path eq \"/terms\" )",
          "https://edge-fixture.invalid/terms", 302, false,
        ],
        [
          "redirect",
          "ssl and ( lower(http.host) eq \"edge-fixture.invalid\" or starts_with(lower(http.host), \"edge-fixture.invalid:\") or lower(http.host) eq \"www.edge-fixture.invalid\" or starts_with(lower(http.host), \"www.edge-fixture.invalid:\") ) and lower(http.request.uri.path) in {\"/conditions\" \"/conditions/\"} and not ( ( lower(http.host) eq \"edge-fixture.invalid\" or starts_with(lower(http.host), \"edge-fixture.invalid:\") ) and http.request.uri.path eq \"/conditions\" )",
          "https://edge-fixture.invalid/conditions", 302, false,
        ],
        [
          "redirect",
          "ssl and ( lower(http.host) eq \"edge-fixture.invalid\" or starts_with(lower(http.host), \"edge-fixture.invalid:\") or lower(http.host) eq \"www.edge-fixture.invalid\" or starts_with(lower(http.host), \"www.edge-fixture.invalid:\") ) and not ( ( lower(http.host) eq \"edge-fixture.invalid\" or starts_with(lower(http.host), \"edge-fixture.invalid:\") ) and ( http.request.uri.path in {\"/terms\" \"/conditions\"} or starts_with(http.request.uri.path, \"/_legal/\") ) )",
          "https://auth.edge-fixture.invalid/", 302, false,
        ],
      ]
    )
    error_message = "the redirect is not each served page to the apex's exact path, then everything else except the apex's served pages and files, each 302 without the query, for both names with and without a port"
  }
}

run "x11b_a_redirect_without_serve_is_a_plain_catch_all_and_no_apex_tunnel_line" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/cloudflare-redirect-without-serve.yaml"
  }

  assert {
    condition = (
      toset(keys(cloudflare_dns_record.host)) == toset(["app.edge-fixture.invalid", "edge-fixture.invalid", "www.edge-fixture.invalid"])
      && [for rule in cloudflare_zero_trust_tunnel_cloudflared_config.this.config.ingress : rule.hostname == null ? "" : rule.hostname] == ["app.edge-fixture.invalid", ""]
    )
    error_message = "without serve the redirect names do not have three records, or the tunnel lines are not the app and the 404"
  }

  assert {
    condition = [for rule in cloudflare_ruleset.apex_redirect[0].rules : [rule.expression, rule.action_parameters.from_value.target_url.value]] == [
      ["ssl and ( lower(http.host) eq \"edge-fixture.invalid\" or starts_with(lower(http.host), \"edge-fixture.invalid:\") or lower(http.host) eq \"www.edge-fixture.invalid\" or starts_with(lower(http.host), \"www.edge-fixture.invalid:\") )", "https://auth.edge-fixture.invalid/"],
    ]
    error_message = "without serve the redirect is not one catch-all with no exclusion"
  }
}

run "x11b_a_catalog_without_a_redirect_plans_no_redirect_ruleset" {
  command = plan

  assert {
    condition     = length(cloudflare_ruleset.apex_redirect) == 0
    error_message = "a redirect ruleset is planned though the catalog has no redirect"
  }
}
