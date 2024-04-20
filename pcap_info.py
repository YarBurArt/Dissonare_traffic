"""
script to search for basic information and anomalies from .pcap
create by ftaxats/Pcap-Analyser
rewrite by yarburart
"""
import re
import os
import struct
from typing import Tuple, Any
import datetime
import logging


logging.basicConfig(level=logging.DEBUG, filename='pcap_info.log',
                    format='%(asctime)s %(levelname)s:%(message)s')

class Error(Exception):
    """put an error shell here"""
    pass
 
class FileTypeError(Error):
    """type error format"""
    def __init__(self, msg, help_tip):
        self.msg = msg
        self.help_tip = help_tip



def _load_pcap(pcap_file_path):
    test_path = str(pcap_file_path)
    # TODO: debug assert logic
    #if not (test_path.endswith(".pcap") or test_path.endswith(".csv")): 
    #    raise FileTypeError(f"File {pcap_file_path} is not a pcap file.", 
    #                         "Try another file with type pcap or csv")
    assert test_path.endswith(".pcap") or test_path.endswith(".csv")  # TODO: csv
    return open(pcap_file_path, 'rb')


class PcapInfoExtractor:
    """
    takes the relative path to the network dump file,
    extracts information and labels from the file by byte at a time
    and returns it as tuples
    """
    def __init__(self, pcap_file_path):
        try:
            self.pcap_data = _load_pcap(pcap_file_path)
            logging.info("File %s is open", pcap_file_path)
        except AssertionError as e:
            logging.error("like a fool's defense ", e)

    def close_file(self):
        """ separate closing as an error may occur """
        self.pcap_data.close()
        logging.info("File %s is close", self.pcap_data.name)

    def global_info(self) -> Tuple[int, str, str, int | Any,
                                   int | Any, int | Any,
                                   int | Any, str, str]:
        """
        to get basic information about the file
        :return: formatted tuple of the most relevant information
        """
        logging.info("start global info func")

        global_header = self.pcap_data.read(24)
        (magic_number, major_version, minor_version, timezone_offset, timestamp_accuracy, snaplen,
         data_link_type) = struct.unpack('<IHHiIII', global_header)
        logging.debug("struct.unpack() has worked")

        if magic_number == 0xa1b2c3d4:
            endianness = 'big'
        elif magic_number == 0xd4c3b2a1:
            endianness = 'little'
        else:
            endianness = 'unknown'

        return (len(global_header), hex(magic_number),
                endianness, major_version, minor_version,
                snaplen, data_link_type,
                timezone_offset, timestamp_accuracy)

    def dhcp_frame_info(self) -> tuple[str, ...]:
        """
        obtaining information about the last or first frame of the dump
        :return: tuple formatted into strings
        """
        logging.info("start dhcp frame info func")
        packet_header = self.pcap_data.read(16)
        timestamp = struct.unpack('I', packet_header[0:4])[0]
        capture_time = timestamp + (struct.unpack('I', packet_header[4:8])[0] / 1000000)

        utc_time = datetime.datetime.utcfromtimestamp(capture_time)
        utc_time_str = utc_time.strftime('%Y-%m-%d %H:%M:%S.%f UTC')
        logging.debug("time functions has worked")

        packet_length = struct.unpack('I', packet_header[8:12])[0]
        packet_data = self.pcap_data.read(packet_length)
        logging.debug("unpack & read functions has worked")

        source_mac = ':'.join([format(b, '02x') for b in packet_data[6:12]])
        destination_mac = ':'.join([format(b, '02x') for b in packet_data[0:6]])

        source_ip = '.'.join([str(b) for b in packet_data[26:30]])
        destination_ip = '.'.join([str(b) for b in packet_data[30:34]])
        logging.debug("string functions has worked")

        hostname = packet_data[34:].decode(errors='ignore').split('\x00')[0]
        logging.debug("get hostname has worked")

        return (utc_time_str, source_mac,
                destination_mac, source_ip,
                destination_ip, hostname)


class PcapUriFinder:
    """
    takes the relative path to the network dump file,
    byte by byte pulls individual uri and domains
    and their frames from the file using regular expressions,
    returns them as frames and links found.
    """
    def __init__(self, pcap_file_path):
        try:
            self.pcap_data = _load_pcap(pcap_file_path)
            logging.info("File %s is open", pcap_file_path)
        except AssertionError as e:
            logging.error("like a fool's defense ", e)

    def close_file(self):
        """ separate closing as an error may occur """
        self.pcap_data.close()
        logging.info("File %s is close", self.pcap_data.name)

    def extract_search_engine_keywords(self) -> dict:
        """
        retrieve search queries and return them in the dictionary
        :return:
            {Search engine: Keywords}
        """
        logging.info("start ext_se_key func")
        pcap_data = self.pcap_data.read()
        decoded_pcap_data = pcap_data.decode("iso-8859-1")

        url_pattern = re.compile(r'https?://\S+')
        urls = url_pattern.findall(decoded_pcap_data)
        query_pattern = re.compile(r'[\?&]q=([^&]+)')
        logging.debug("first regulars found")

        searches = {}
        for url in urls:
            match = re.search(r'https?://(www\.)?([a-zA-Z0-9_-]+)\.', url)
            if match:
                search_engine = match.group(2)
                if search_engine not in searches:
                    searches[search_engine] = []
                logging.debug("engine %s found", search_engine)

            match = query_pattern.search(url)
            if match:
                keyword = match.group(1)
                searches[search_engine].append(keyword)
                logging.debug("keyword %s found", keyword)

        if not searches:
            logging.error("searches are empty")
            return {"google": "cat"}

        return searches

    def find_website_uris_by_domain(self, domain: str = '.com') -> list:
        """
        :param domain: dot domain name
        :return: list of links found (assuming they are suspicious)
        """
        logging.info("start f_wb_u_dot func")
        domain_extension_bytes = domain.encode()
        url_pattern = rb"https?://\S+?" + re.escape(domain_extension_bytes) + rb"\b"

        website_pattern = re.compile(url_pattern)
        file_content = self.pcap_data.read()
        website_urls = website_pattern.findall(file_content)

        return website_urls


def main():
    """ tests from crutches """
    print("""
    Tests for this file are located in pcap_info_test.py
    Start only in manual mode via "pytest" 
    """)


if __name__ == '__main__':
    main()
