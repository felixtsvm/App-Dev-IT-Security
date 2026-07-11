"""
Tests für die REST-API des IP Threat Checkers.

Externe API-Aufrufe werden durch Testdaten ersetzt. Dadurch sind die
Tests unabhängig von Internetverbindung, API-Schlüsseln und externen Diensten.
"""

import pytest

import api
from api import app


@pytest.fixture
def client():
    """
    Erstellt einen Flask-Testclient für die API-Tests.
    """
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def mock_successful_scan(monkeypatch):
    """
    Ersetzt den vollständigen Scan durch ein erfolgreiches Testergebnis.
    """

    def fake_scan(ip_address):
        return {
            "success": True,
            "final_score": 42,
            "risk_level": "Mittleres Risiko"
        }

    monkeypatch.setattr(
        api,
        "run_complete_scan",
        fake_scan
    )


def test_missing_ip(client):
    """
    Ohne IP-Adresse muss die API HTTP 400 zurückgeben.
    """
    response = client.get("/check")

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False


def test_invalid_ip(client):
    """
    Eine formal ungültige IP-Adresse muss abgelehnt werden.
    """
    response = client.get(
        "/check?ip=999.999.999.999"
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False
    assert data["error"] == "Die IP-Adresse ist ungültig."


def test_valid_ip_returns_json(
    client,
    mock_successful_scan
):
    """
    Eine erfolgreiche Anfrage muss eine JSON-Antwort liefern.
    """
    response = client.get("/check?ip=8.8.8.8")

    assert response.status_code == 200
    assert response.is_json


def test_successful_response_contains_expected_fields(
    client,
    mock_successful_scan
):
    """
    Eine erfolgreiche Antwort muss alle benötigten Felder enthalten.
    """
    response = client.get("/check?ip=8.8.8.8")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["ip_address"] == "8.8.8.8"
    assert data["final_score"] == 42
    assert "risk_level" in data
    assert "handlungsempfehlung" in data


def test_medium_score_returns_manual_review(
    client,
    mock_successful_scan
):
    """
    Ein mittlerer Risiko-Score soll eine manuelle Prüfung empfehlen.
    """
    response = client.get("/check?ip=8.8.8.8")

    assert response.status_code == 200

    data = response.get_json()

    assert data["final_score"] == 42
    assert data["handlungsempfehlung"] == "Manuelle Prüfung"


def test_scan_failure_returns_http_500(
    client,
    monkeypatch
):
    """
    Ein interner Scanfehler muss als HTTP 500 ausgegeben werden.
    """

    def fake_failed_scan(ip_address):
        return {
            "success": False,
            "error": "Testfehler bei der Datenabfrage"
        }

    monkeypatch.setattr(
        api,
        "run_complete_scan",
        fake_failed_scan
    )

    response = client.get("/check?ip=8.8.8.8")

    assert response.status_code == 500

    data = response.get_json()

    assert data["success"] is False
    assert data["error"] == "Testfehler bei der Datenabfrage"