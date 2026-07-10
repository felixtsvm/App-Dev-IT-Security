"""
Unit-Tests für das Cache-Modul.

Getestet werden:
- Cache-Miss
- Speichern und Auslesen
- Trennung verschiedener IP-Adressen
- Überschreiben bestehender Einträge
- Deepcopy beim Speichern
- Deepcopy bei der Rückgabe
- Ablauf der TTL
- Verhalten exakt an der TTL-Grenze
"""

import cache


def setup_function():
    """
    Wird vor jedem Test ausgeführt.

    Der Cache wird geleert, damit sich die Tests
    nicht gegenseitig beeinflussen.
    """
    cache.CACHE.clear()


def test_empty_cache_returns_none():
    """
    Für eine nicht gespeicherte IP-Adresse soll None zurückgegeben werden.
    """
    result = cache.get_cached_result("8.8.8.8")

    assert result is None


def test_cache_hit_returns_saved_result():
    """
    Ein gespeichertes Ergebnis soll wieder zurückgegeben werden.
    """
    ip_address = "8.8.8.8"

    expected_result = {
        "success": True,
        "final_score": 10
    }

    cache.set_cached_result(ip_address, expected_result)

    result = cache.get_cached_result(ip_address)

    assert result == expected_result


def test_different_ips_are_stored_separately():
    """
    Verschiedene IP-Adressen dürfen nicht dieselben Cache-Daten erhalten.
    """
    cache.set_cached_result(
        "8.8.8.8",
        {"final_score": 10}
    )

    cache.set_cached_result(
        "1.1.1.1",
        {"final_score": 55}
    )

    first_result = cache.get_cached_result("8.8.8.8")
    second_result = cache.get_cached_result("1.1.1.1")

    assert first_result["final_score"] == 10
    assert second_result["final_score"] == 55


def test_existing_entry_is_overwritten():
    """
    Ein neuer Eintrag für dieselbe IP-Adresse soll den alten ersetzen.
    """
    ip_address = "8.8.8.8"

    cache.set_cached_result(
        ip_address,
        {"final_score": 10}
    )

    cache.set_cached_result(
        ip_address,
        {"final_score": 70}
    )

    result = cache.get_cached_result(ip_address)

    assert result["final_score"] == 70


def test_result_is_copied_when_saved():
    """
    Änderungen am ursprünglichen Dictionary nach dem Speichern
    dürfen den Cache-Inhalt nicht verändern.
    """
    ip_address = "9.9.9.9"

    original_result = {
        "success": True,
        "threat_data": {
            "score": 10
        }
    }

    cache.set_cached_result(ip_address, original_result)

    original_result["threat_data"]["score"] = 99

    cached_result = cache.get_cached_result(ip_address)

    assert cached_result["threat_data"]["score"] == 10


def test_cached_result_is_returned_as_copy():
    """
    Änderungen am zurückgegebenen Ergebnis dürfen
    den gespeicherten Cache-Inhalt nicht verändern.
    """
    ip_address = "4.4.4.4"

    cache.set_cached_result(
        ip_address,
        {
            "success": True,
            "geo_data": {
                "country_code": "DE"
            }
        }
    )

    first_result = cache.get_cached_result(ip_address)
    first_result["geo_data"]["country_code"] = "RU"

    second_result = cache.get_cached_result(ip_address)

    assert second_result["geo_data"]["country_code"] == "DE"


def test_expired_entry_returns_none(monkeypatch):
    """
    Ein Eintrag soll nach Ablauf der TTL nicht mehr zurückgegeben werden.

    Die Zeit wird simuliert, damit der Test nicht zehn Minuten warten muss.
    """
    ip_address = "1.0.0.1"

    monkeypatch.setattr(
        cache.time,
        "time",
        lambda: 1000.0
    )

    cache.set_cached_result(
        ip_address,
        {"final_score": 20}
    )

    expired_time = 1000.0 + cache.CACHE_TTL_SECONDS + 1

    monkeypatch.setattr(
        cache.time,
        "time",
        lambda: expired_time
    )

    result = cache.get_cached_result(ip_address)

    assert result is None


def test_expired_entry_is_deleted(monkeypatch):
    """
    Ein abgelaufener Eintrag soll aus dem CACHE-Dictionary entfernt werden.
    """
    ip_address = "208.67.222.222"

    monkeypatch.setattr(
        cache.time,
        "time",
        lambda: 2000.0
    )

    cache.set_cached_result(
        ip_address,
        {"final_score": 30}
    )

    expired_time = 2000.0 + cache.CACHE_TTL_SECONDS + 1

    monkeypatch.setattr(
        cache.time,
        "time",
        lambda: expired_time
    )

    cache.get_cached_result(ip_address)

    assert ip_address not in cache.CACHE


def test_entry_is_valid_exactly_at_ttl(monkeypatch):
    """
    Ein Eintrag ist laut eurem aktuellen Code genau an der TTL-Grenze
    noch gültig, weil erst bei age > CACHE_TTL_SECONDS gelöscht wird.
    """
    ip_address = "4.2.2.2"

    monkeypatch.setattr(
        cache.time,
        "time",
        lambda: 3000.0
    )

    expected_result = {
        "final_score": 25
    }

    cache.set_cached_result(
        ip_address,
        expected_result
    )

    exact_ttl_time = 3000.0 + cache.CACHE_TTL_SECONDS

    monkeypatch.setattr(
        cache.time,
        "time",
        lambda: exact_ttl_time
    )

    result = cache.get_cached_result(ip_address)

    assert result == expected_result
    assert ip_address in cache.CACHE


def test_cache_ttl_is_600_seconds():
    """
    Die Lebensdauer des Caches soll zehn Minuten betragen.
    """
    assert cache.CACHE_TTL_SECONDS == 600