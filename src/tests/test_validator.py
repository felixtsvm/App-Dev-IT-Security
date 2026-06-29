from validator import ip_testung

def test_valid_ipv4():
    assert ip_testung("8.8.8.8") is True

def test_valid_ipv6():
    assert ip_testung("2001:4860:4860::8888") is True

def test_invalid_ip():
    assert ip_testung("999.999.999.999") is False