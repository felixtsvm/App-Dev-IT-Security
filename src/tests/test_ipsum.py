from apis.ipsum import get_ipsum_info
import apis.ipsum as ipsum


class FakeResponse:
    """
    Simuliert eine erfolgreiche HTTP-Antwort des GitHub-IPsum-Feeds.
    """

    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_ip_is_found(monkeypatch):
    """
    Eine IP-Adresse, die im Feed enthalten ist,
    soll als Blacklist-Treffer erkannt werden.
    """

    fake_feed = """
# Kommentar
8.8.8.8
1.1.1.1
185.220.101.1
"""

    monkeypatch.setattr(
        ipsum.requests,
        "get",
        lambda url, timeout: FakeResponse(fake_feed)
    )

    result = get_ipsum_info("185.220.101.1")

    assert result["listed"] is True
    assert "Kritisch" in result["status_text"]


def test_ip_is_not_found(monkeypatch):
    """
    Eine IP-Adresse, die nicht im Feed vorkommt,
    soll als unauffällig erkannt werden.
    """

    fake_feed = """
# Kommentar
8.8.8.8
1.1.1.1
"""

    monkeypatch.setattr(
        ipsum.requests,
        "get",
        lambda url, timeout: FakeResponse(fake_feed)
    )

    result = get_ipsum_info("9.9.9.9")

    assert result["listed"] is False
    assert result["status_text"] == "Sauber oder unauffällig"


def test_comment_lines_are_ignored(monkeypatch):
    """
    IP-Adressen in Kommentarzeilen dürfen
    nicht als Treffer erkannt werden.
    """

    fake_feed = """
# 8.8.8.8
1.1.1.1
"""

    monkeypatch.setattr(
        ipsum.requests,
        "get",
        lambda url, timeout: FakeResponse(fake_feed)
    )

    result = get_ipsum_info("8.8.8.8")

    assert result["listed"] is False


def test_only_exact_ip_matches(monkeypatch):
    """
    Es darf nur auf exakte IP-Adressen geprüft werden.
    """

    fake_feed = """
185.220.101.10
"""

    monkeypatch.setattr(
        ipsum.requests,
        "get",
        lambda url, timeout: FakeResponse(fake_feed)
    )

    result = get_ipsum_info("185.220.101.1")

    assert result["listed"] is False


def test_empty_feed(monkeypatch):
    """
    Ein leerer Feed soll keine Treffer liefern.
    """

    monkeypatch.setattr(
        ipsum.requests,
        "get",
        lambda url, timeout: FakeResponse("")
    )

    result = get_ipsum_info("8.8.8.8")

    assert result["listed"] is False


def test_network_error(monkeypatch):
    """
    Netzwerkfehler sollen sauber abgefangen werden.
    """

    def raise_error(url, timeout):
        raise Exception("Netzwerkfehler")

    monkeypatch.setattr(
        ipsum.requests,
        "get",
        raise_error
    )

    result = get_ipsum_info("8.8.8.8")

    assert "error" in result
    assert "Anfragefehler IPsum" in result["error"]