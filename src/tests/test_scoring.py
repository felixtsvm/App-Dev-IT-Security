from scoring import calculate_final_score, calculate_risk_level


def create_threat_data(
    score=0,
    whitelisted=False,
    hostname="example.com",
    domain="example.com",
    usage_type="Residential",
    reports=0,
    tor=False
):
    return {
        "score": score,
        "whitelisted": whitelisted,
        "hostname": hostname,
        "domain": domain,
        "usage_type": usage_type,
        "reports": reports,
        "tor": tor
    }


def create_blacklist_data(listed=False):
    return {
        "listed": listed
    }


def create_geo_data(country_code="DE"):
    return {
        "country_code": country_code
    }


def test_clean_ip_has_zero_score():
    result = calculate_final_score(
        create_threat_data(),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 0


def test_abuse_score_is_weighted():
    result = calculate_final_score(
        create_threat_data(score=50),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 20


def test_blacklist_adds_30_points():
    result = calculate_final_score(
        create_threat_data(),
        create_blacklist_data(listed=True),
        create_geo_data()
    )

    assert result == 30


def test_tor_adds_20_points():
    result = calculate_final_score(
        create_threat_data(tor=True),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 20


def test_data_center_adds_10_points():
    result = calculate_final_score(
        create_threat_data(
            usage_type="Data Center/Web Hosting"
        ),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 10


def test_more_than_50_reports_adds_10_points():
    result = calculate_final_score(
        create_threat_data(reports=51),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 10


def test_dynamic_dns_adds_15_points():
    result = calculate_final_score(
        create_threat_data(
            hostname="test.duckdns.org"
        ),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 15


def test_consumer_hostname_adds_15_points():
    result = calculate_final_score(
        create_threat_data(
            hostname="dsl.example-provider.de"
        ),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 15


def test_high_risk_country_adds_15_points():
    result = calculate_final_score(
        create_threat_data(),
        create_blacklist_data(),
        create_geo_data(country_code="RU")
    )

    assert result == 15


def test_whitelist_reduces_score():
    result = calculate_final_score(
        create_threat_data(
            score=100,
            whitelisted=True
        ),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 20


def test_score_cannot_be_negative():
    result = calculate_final_score(
        create_threat_data(
            score=10,
            whitelisted=True
        ),
        create_blacklist_data(),
        create_geo_data()
    )

    assert result == 0


def test_score_is_limited_to_100():
    result = calculate_final_score(
        create_threat_data(
            score=100,
            whitelisted=False,
            hostname="dynamic.test.duckdns.org",
            domain="duckdns.org",
            usage_type="Data Center/Web Hosting",
            reports=500,
            tor=True
        ),
        create_blacklist_data(listed=True),
        create_geo_data(country_code="RU")
    )

    assert result == 100


def test_low_risk_level():
    result = calculate_risk_level(29)

    assert result["level"] == "Niedriges Risiko"
    assert result["action"] == "Zulassen"


def test_medium_risk_level():
    result = calculate_risk_level(30)

    assert result["level"] == "Mittleres Risiko"
    assert result["action"] == "Manuelle Prüfung"


def test_high_risk_level():
    result = calculate_risk_level(70)

    assert result["level"] == "Hohes Risiko"
    assert result["action"] == "Sperren"