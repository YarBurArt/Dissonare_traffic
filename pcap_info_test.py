from pcap_info import (_load_pcap,
                       PcapInfoExtractor,
                       PcapUriFinder)
from typing import Tuple, Any

file_test = "phishingattack.pcap"
pcap_info = PcapInfoExtractor(file_test)
pcap_finder = PcapUriFinder(file_test)


def test_global_info():
    res = pcap_info.global_info()
    # check types
    assert res
    assert isinstance(res, tuple) or list(map(type, res)) \
           == Tuple[int, str, str, int,
                    int, int, int]
    # check values
    assert res == (24, "0xa1b2c3d4", "big", 2, 4, 262144, 1)


def test_dhcp_frame_info():
    res = pcap_info.dhcp_frame_info()
    assert res
    assert isinstance(res, tuple) or list(map(type, res)) \
           == tuple[str, ...]
    assert res == (
        "2017-04-18 02:00:24.868504 UTC",
        "6c:0b:84:6a:1d:d8",
        "00:23:eb:6b:ff:2a",
        "192.168.1.100",
        "52.84.125.48",
        "\u0014\u0001CI\r(\u0010\u0002s")


def test_extract_search_engine_keywords():
    res: dict = pcap_finder.extract_search_engine_keywords()
    assert all(isinstance(i, str) for i in res.keys())
    assert list(res.keys()) == \
        ['paypal', 'w3', 'purl',
         'day', 'ns', 'support', 'google']


def test_close_file():
    assert not pcap_info.close_file()
    assert not pcap_finder.close_file()
