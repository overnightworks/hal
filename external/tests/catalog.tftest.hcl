mock_provider "cloudflare" {
  mock_data "cloudflare_zone" {
    defaults = { id = "0123456789abcdef0123456789abcdef" }
  }
}

variables {
  catalog_file = "tests/fixtures/empty.yaml"
  tunnel_id    = "tunnel-id"
}

run "an_empty_catalog_has_no_services" {
  command = plan

  assert {
    condition     = length(local.fleet.services) == 0
    error_message = "the empty fixture has no services"
  }
}
