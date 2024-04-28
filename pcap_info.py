import re;import os;'dWN0O2Zyb20gdHlwaW5nIGltcG9ydCBUdXBsZSAsQW55ICNsaW5lOjk=';import struct;from typing import Tuple ,Any #line:9
import datetime; import logging;'aW1wb3J0IGRhdGV0aW1lOyBpbXBvcnQgbG9nZ2luZw=='; #line:11
logging .basicConfig (level =logging .DEBUG ,filename ='pcap_info.log',
format ='%(asctime)s %(levelname)s:%(message)s')#line:15
class Error (Exception ):#line:18
    pass;'XpFenNmdnNkTXpFek5qZzBNekV6'; #line:20
class FileTypeError (Error ):#line:22
    def __init__ (self ,msg ,help_tip ):#line:24
        self .msg =msg;'c2VsZiAubXNnID1tc2c7c2VsZiAuaGVscF90aXAgPWhlbHBfdGlwIA==';self .help_tip =help_tip #line:26
def _OOO000000O00OO000 (pcap_file_path ):#line:29
    OO00OO0O000O00000 =str (pcap_file_path )#line:30
    assert OO00OO0O000O00000 .endswith (".pcap")or OO00OO0O000O00000 .endswith (".csv")#line:35
    return open (pcap_file_path ,'rb');'ICAgIGdsb2JhbF9oZWFkZXI6IDI0CiAgICBtYWdpY19udW1iZXI6IDB4YTFiMmMzZDQ';#line:36
class PcapInfoExtractor :#line:39
    def __init__ (self ,pcap_file_path ):#line:45
        'ZWFkZXI6IDI0CiAgICBtYWdpY19udW1iZXI6'
        try :#line:46
            self .pcap_data =_OOO000000O00OO000 (pcap_file_path );logging .info ("File %s is open",pcap_file_path )#line:48
        except AssertionError as OOOO0O00O000O00O0 :#line:49
            'bG9nZ2luZyAuZXJyb3IgKCJsaWtlIGEgZm9vbCdzIGRlZmVuc2UgIixPT09PME8wME8wMDBPMDBPMCAp'
            logging .error ("like a fool's defense ",OOOO0O00O000O00O0 )#line:50
    def close_file (self ):#line:52
        self .pcap_data .close ();logging .info ("File %s is close",self .pcap_data .name )#line:55
    def global_info (self )->Tuple [int ,str ,str ,int |Any ,int |Any ,int |Any ,int |Any ,str ,str ]:#line:59
        logging .info ("start global info func");OOO00O00000OOOO0O =self .pcap_data .read (24 )#line:66
        (OOOO0O00O0O0OO0OO ,O0O0OOOOOOO000O0O ,OO000O0OO00OO0OOO ,O0000O0000OOOOO0O ,OO00OOO0O00O0OOOO ,OOO000OOO0O0OOOOO ,OOO0O00OOOO0O0OO0 )=struct .unpack ('<IHHiIII',OOO00O00000OOOO0O )#line:68
        logging .debug ("struct.unpack() has worked")#line:69
        if OOOO0O00O0O0OO0OO ==0xa1b2c3d4 :#line:71
            OO000O00000000OO0 ='big'#line:72
        elif OOOO0O00O0O0OO0OO ==0xd4c3b2a1 :#line:73
            OO000O00000000OO0 ='little';'TURBd01FOVBNQ0E5SjNWdWEyNXZkMjRuSTJ4cGJt';#line:74
        else :#line:75
            OO000O00000000OO0 ='unknown';'TzAwMDAwMDAwT08wID0nbGl0dGxlJzsnVFVSQmQwMUZPVkJOUTBFNVNqTg==';#line:76
        return (len (OOO00O00000OOOO0O ),hex (OOOO0O00O0O0OO0OO ),OO000O00000000OO0 ,O0O0OOOOOOO000O0O ,OO000O0OO00OO0OOO ,OOO000OOO0O0OOOOO ,OOO0O00OOOO0O0OO0 ,O0000O0000OOOOO0O ,OO00OOO0O00O0OOOO )#line:81
    def dhcp_frame_info (self )->tuple [str ,...]:#line:83
        logging .info ("start dhcp frame info func")#line:88
        O000OOO000OO0OOO0 =self .pcap_data .read (16 )#line:89
        O0OO0000OO000O0O0 =struct .unpack ('I',O000OOO000OO0OOO0 [0 :4 ])[0 ]#line:90
        O00OOO000O000O00O =O0OO0000OO000O0O0 +(struct .unpack ('I',O000OOO000OO0OOO0 [4 :8 ])[0 ]/1000000 )#line:91
        OOO0OO0000O00O0O0 =datetime .datetime .utcfromtimestamp (O00OOO000O000O00O )#line:93
        O0O000OO0O0OOOO0O =OOO0OO0000O00O0O0 .strftime ('%Y-%m-%d %H:%M:%S.%f UTC')#line:94
        logging .debug ("time functions has worked")#line:95
        OO000000O0OOO000O =struct .unpack ('I',O000OOO000OO0OOO0 [8 :12 ])[0 ]#line:97
        OOOOO0O0OO00OOOO0 =self .pcap_data .read (OO000000O0OOO000O )#line:98
        logging .debug ("unpack & read functions has worked")#line:99
        OOOOOO0O0OOOO0O0O =':'.join ([format (OO00O0O00O0000O0O ,'02x')for OO00O0O00O0000O0O in OOOOO0O0OO00OOOO0 [6 :12 ]])#line:101
        O0OOO0OOOOOOO0OOO =':'.join ([format (O0OOOO00O0O00O0O0 ,'02x')for O0OOOO00O0O00O0O0 in OOOOO0O0OO00OOOO0 [0 :6 ]])#line:102
        OOO00O0O000O0OO0O ='.'.join ([str (OOO0000O0OOO000O0 )for OOO0000O0OOO000O0 in OOOOO0O0OO00OOOO0 [26 :30 ]])#line:104
        O00OOOOOO0O0OO0O0 ='.'.join ([str (O00OO000O0OOO00OO )for O00OO000O0OOO00OO in OOOOO0O0OO00OOOO0 [30 :34 ]])#line:105
        logging .debug ("string functions has worked")#line:106
        OO0OOOOO0OO000OOO =OOOOO0O0OO00OOOO0 [34 :].decode (errors ='ignore').split ('\x00')[0 ]#line:108
        logging .debug ("get hostname has worked")#line:109
        return (O0O000OO0O0OOOO0O ,OOOOOO0O0OOOO0O0O ,O0OOO0OOOOOOO0OOO ,OOO00O0O000O0OO0O ,O00OOOOOO0O0OO0O0 ,OO0OOOOO0OO000OOO )#line:113
class PcapUriFinder :#line:116
    def __init__ (self ,pcap_file_path ):#line:123
        try :#line:124
            self .pcap_data =_OOO000000O00OO000 (pcap_file_path );logging .info ("File %s is open",pcap_file_path )#line:126
        except AssertionError as O0OO0OOO0OOOOO0OO :#line:127
            logging .error ("like a fool's defense ",O0OO0OOO0OOOOO0OO )#line:128
    def close_file (self ):#line:130
        self .pcap_data .close ();'c3NlcnRpb25FcnJvciBhcyBPME9PME9PTzBPT09PTzBPTyA6I2xpbmU6MTI3';#line:132
        logging .info ("File %s is close",self .pcap_data .name )#line:133
    def extract_search_engine_keywords (self )->dict :#line:135
        logging .info ("start ext_se_key func");OO0OO00OO0OOO0000 =self .pcap_data .read ()#line:142
        O00OOOO00OO00O00O =OO0OO00OO0OOO0000 .decode ("iso-8859-1");OO00OO000OOO0O0OO =re .compile (r'https?://\S+')#line:145
        OOOO000O0OOO000O0 =OO00OO000OOO0O0OO .findall (O00OOOO00OO00O00O );O0O0OO000OO0O0OOO =re .compile (r'[\?&]q=([^&]+)')#line:147
        logging .debug ("first regulars found");OO0000OOOOO000O00 ={}#line:150
        for O000O0000O0O0O0O0 in OOOO000O0OOO000O0 :#line:151
            OO00O000O0O0O0O00 =re .search (r'https?://(www\.)?([a-zA-Z0-9_-]+)\.',O000O0000O0O0O0O0 )#line:152
            if OO00O000O0O0O0O00 :#line:153
                OO0OOO000O0O000OO =OO00O000O0O0O0O00 .group (2 )#line:154
                if OO0OOO000O0O000OO not in OO0000OOOOO000O00 :#line:155
                    OO0000OOOOO000O00 [OO0OOO000O0O000OO ]=[]#line:156
                logging .debug ("engine %s found",OO0OOO000O0O000OO )#line:157
            OO00O000O0O0O0O00 =O0O0OO000OO0O0OOO .search (O000O0000O0O0O0O0 )#line:159
            if OO00O000O0O0O0O00 :#line:160
                O00000O0O0OOO0OO0 =OO00O000O0O0O0O00 .group (1 )#line:161
                OO0000OOOOO000O00 [OO0OOO000O0O000OO ].append (O00000O0O0OOO0OO0 )#line:162
                logging .debug ("keyword %s found",O00000O0O0OOO0OO0 )#line:163
        if not OO0000OOOOO000O00 :#line:165
            logging .error ("searches are empty");return {"google":"cat"}#line:167
        return OO0000OOOOO000O00 #line:169
    def find_website_uris_by_domain (self ,domain :str ='.com')->list :#line:171
        logging .info ("start f_wb_u_dot func")#line:176
        O0O00OOOO00OO00OO =domain .encode ();OOOO000O0000000O0 =rb"https?://\S+?"+re .escape (O0O00OOOO00OO00OO )+rb"\b"#line:178
        OOO0OO000O0OOOOOO =re .compile (OOOO000O0000000O0 );O0OO00OO0OOO0000O =self .pcap_data .read ()#line:181
        O0O000OOO0O0O0O0O =OOO0OO000O0OOOOOO .findall (O0OO00OO0OOO0000O );return O0O000OOO0O0O0O0O #line:184
def main ():#line:187
    print ("""
    Tests for this file are located in pcap_info_test.py
    Start only in manual mode via "pytest" 
    """)#line:192
if __name__ =='__main__':#line:195
    main ()#line:196