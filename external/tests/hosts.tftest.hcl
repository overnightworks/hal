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

run "the_wildcard_catalog_yields_the_expected_hosts" {
  command = plan

  # Refresh-only reads the locals without planning the tunnel configuration, which refuses a wildcard until X8b.
  plan_options {
    mode = refresh-only
  }

  variables {
    catalog_file = "tests/fixtures/hosts-wildcard.yaml"
  }

  assert {
    condition     = local.hosts == jsondecode(file("tests/fixtures/hosts-wildcard.expected.json"))
    error_message = "local.hosts differs from the expectation the Python reader is also held to"
  }
}

run "the_plain_catalog_yields_the_expected_hosts" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/hosts-plain.yaml"
  }

  assert {
    condition     = local.hosts == jsondecode(file("tests/fixtures/hosts-plain.expected.json"))
    error_message = "local.hosts differs from the expectation the Python reader is also held to"
  }
}

run "an_empty_catalog_has_no_hosts" {
  command = plan

  variables {
    catalog_file = "tests/fixtures/empty.yaml"
  }

  assert {
    condition     = length(local.hosts) == 0
    error_message = "the empty fixture has no hosts"
  }
}
