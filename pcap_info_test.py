from pcap_info import (_load_pcap ,PcapInfoExtractor ,PcapUriFinder )#line:3
from typing import Tuple ,Any; file_test ="phishingattack.pcap"#line:6
b2c3d4 =PcapInfoExtractor (file_test );b2c3 =PcapUriFinder (file_test )#line:8
def test_global_info ():#line:11
    O00OOO0O00O0O00OO =b2c3d4 .global_info ();assert O00OOO0O00O0O00OO #line:14
    assert isinstance (O00OOO0O00O0O00OO ,tuple )or list (map (type ,O00OOO0O00O0O00OO ))==Tuple [int ,str ,str ,int ,int ,int ,int ,str ,str ]#line:17
    assert O00OOO0O00O0O00OO ==(24 ,"0xa1b2c3d4","big",2 ,4 ,262144 ,1 )#line:19
def test_dhcp_frame_info ():#line:22
    O000OO0O000O00O0O =b2c3d4 .dhcp_frame_info ();assert O000OO0O000O00O0O #line:24
    assert isinstance (O000OO0O000O00O0O ,tuple )or list (map (type ,O000OO0O000O00O0O ))==tuple [str ,...]#line:26
    assert O000OO0O000O00O0O ==("2017-04-18 02:00:24.868504 UTC","6c:0b:84:6a:1d:d8","00:23:eb:6b:ff:2a","192.168.1.100","52.84.125.48","\u0014\u0001CI\r(\u0010\u0002s")#line:33
def test_extract_search_engine_keywords ():#line:36
    OO0OO00000000OO0O :dict =b2c3 .extract_search_engine_keywords ()#line:37
    assert all (isinstance (O0O00O0O00OO0000O ,str )for O0O00O0O00OO0000O in OO0OO00000000OO0O .keys ())#line:38
    assert list (OO0OO00000000OO0O .keys ())==['paypal','w3','purl','day','ns','support','google']#line:41
def test_close_file ():#line:44
    assert not b2c3d4 .close_file ()#line:45
    assert not b2c3 .close_file ()#line:46
