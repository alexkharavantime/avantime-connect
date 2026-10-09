"""Pure profile contract checks; no running Mongo or WireGuard required."""
import ipaddress
import pytest
from app.services.access import profile_fields


@pytest.mark.parametrize('environments,expected_routes,rdp', [
    (['dev'], '10.20.0.20/32, 10.40.0.10/32', '10.20.0.20'),
    (['prod'], '10.40.0.0/24', '10.40.0.20'),
    (['dev', 'prod'], '10.20.0.20/32, 10.40.0.0/24', '10.40.0.20'),
])
def test_dns_reachable_without_expanding_environment_grant(environments, expected_routes, rdp):
    profile = profile_fields(environments, 7)
    assert profile['allowed_ips'] == expected_routes
    assert profile['rdp_host'] == rdp
    assert profile['access_revision'] == 7
    assert profile['environments'] == environments
    routes = [ipaddress.ip_network(route) for route in expected_routes.split(', ')]
    assert any(ipaddress.ip_address('10.40.0.10') in route for route in routes)
    assert not any(ipaddress.ip_address('1.1.1.1') in route for route in routes)
    assert any(ipaddress.ip_address('10.40.0.20') in route for route in routes) == ('prod' in environments)
