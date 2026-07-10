from api import app


def test_missing_ip():
    """
    Es wurde keine IP übergeben.
    Erwartet wird HTTP 400.
    """

    client = app.test_client()

    response = client.get("/check")

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False


def test_invalid_ip():
    """
    Ungültige IP-Adresse.
    """

    client = app.test_client()

    response = client.get("/check?ip=999.999.999.999")

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False
    assert data["error"] == "Die IP-Adresse ist ungültig."


def test_valid_ip_returns_json():
    """
    Für eine gültige IP soll zumindest eine JSON-Antwort
    zurückgegeben werden.
    """

    client = app.test_client()

    response = client.get("/check?ip=8.8.8.8")

    assert response.is_json


def test_response_contains_success():
    """
    Die Antwort soll immer das Feld success besitzen.
    """

    client = app.test_client()

    response = client.get("/check?ip=8.8.8.8")

    data = response.get_json()

    assert "success" in data


def test_response_contains_ip():
    """
    Bei erfolgreichem Scan muss die IP-Adresse zurückgegeben werden.
    """

    client = app.test_client()

    response = client.get("/check?ip=8.8.8.8")

    data = response.get_json()

    if response.status_code == 200:
        assert data["ip_address"] == "8.8.8.8"


def test_response_contains_score():
    """
    Erfolgreiche Antworten enthalten den Final Risk Score.
    """

    client = app.test_client()

    response = client.get("/check?ip=8.8.8.8")

    data = response.get_json()

    if response.status_code == 200:
        assert "final_score" in data


def test_response_contains_risk_level():
    """
    Erfolgreiche Antworten enthalten das Risiko-Level.
    """

    client = app.test_client()

    response = client.get("/check?ip=8.8.8.8")

    data = response.get_json()

    if response.status_code == 200:
        assert "risk_level" in data


def test_response_contains_recommendation():
    """
    Erfolgreiche Antworten enthalten eine Handlungsempfehlung.
    """

    client = app.test_client()

    response = client.get("/check?ip=8.8.8.8")

    data = response.get_json()

    if response.status_code == 200:
        assert "handlungsempfehlung" in data


def test_valid_ip_returns_http_200_or_500():
    """
    Je nach Erreichbarkeit der externen APIs
    wird HTTP 200 oder HTTP 500 akzeptiert.
    """

    client = app.test_client()

    response = client.get("/check?ip=8.8.8.8")

    assert response.status_code in [200, 500]