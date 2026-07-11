"""
Tests für die Validierung von IPv4- und IPv6-Adressen.
"""

from validator import ip_testung


def test_valid_ipv4():
    assert ip_testung("8.8.8.8") is True


def test_valid_ipv6():
    assert ip_testung("2001:4860:4860::8888") is True


def test_invalid_ip():
    assert ip_testung("999.999.999.999") is False


def test_empty_input():
    assert ip_testung("") is False


def test_text_input():
    assert ip_testung("keine-ip") is False


def test_private_ipv4():
    assert ip_testung("192.168.0.1") is True