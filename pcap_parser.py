"""
PCAP Packet Capture Parser and Network Traffic Simulator.
Reads standard .pcap files using Scapy when available, or a fallback pure-Python binary PCAP reader,
and provides synthetic traffic generators for attack demonstration.
"""
import struct
import time
import socket
from datetime import datetime
from utils.logger import logger

class PCAPParser:
    @staticmethod
    def parse_file(filepath, max_packets=500):
        """
        Parses a PCAP file and returns a list of normalized packet dictionaries.
        """
        # Try Scapy first
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
            packets = rdpcap(filepath)
            parsed_list = []
            for i, pkt in enumerate(packets):
                if i >= max_packets:
                    break
                if IP in pkt:
                    proto = 'TCP' if TCP in pkt else ('UDP' if UDP in pkt else ('ICMP' if ICMP in pkt else 'IP'))
                    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
                    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
                    flags = str(pkt[TCP].flags) if TCP in pkt else None

                    parsed_list.append({
                        'source_ip': pkt[IP].src,
                        'dest_ip': pkt[IP].dst,
                        'source_port': sport,
                        'dest_port': dport,
                        'protocol': proto,
                        'packet_size': len(pkt),
                        'tcp_flags': flags,
                        'traffic_direction': 'INBOUND',
                        'payload_preview': str(bytes(pkt.payload))[:50],
                        'timestamp': datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S')
                    })
            if parsed_list:
                logger.info(f"Scapy parsed {len(parsed_list)} packets from {filepath}")
                return parsed_list
        except ImportError:
            logger.info("Scapy not installed. Using pure-Python binary PCAP parser fallback.")
        except Exception as e:
            logger.warning(f"Scapy parse failed: {e}. Falling back to binary PCAP reader.")

        # Fallback pure-Python PCAP parser
        return PCAPParser._parse_binary_pcap(filepath, max_packets)

    @staticmethod
    def _parse_binary_pcap(filepath, max_packets=500):
        """
        Pure-Python fallback reader for standard libpcap format files.
        """
        packets = []
        try:
            with open(filepath, 'rb') as f:
                # Read PCAP Global Header (24 bytes)
                global_hdr = f.read(24)
                if len(global_hdr) < 24:
                    return []
                magic = struct.unpack('<I', global_hdr[:4])[0]
                is_little_endian = magic in (0xa1b2c3d4, 0xa1b23c4d)
                endian = '<' if is_little_endian else '>'

                pkt_count = 0
                while pkt_count < max_packets:
                    # Packet Header (16 bytes): ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
                    pkt_hdr = f.read(16)
                    if len(pkt_hdr) < 16:
                        break
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', pkt_hdr)
                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < incl_len:
                        break

                    # Parse Ethernet (14 bytes)
                    if len(pkt_data) > 14:
                        eth_type = struct.unpack('!H', pkt_data[12:14])[0]
                        if eth_type == 0x0800:  # IPv4
                            ip_data = pkt_data[14:]
                            if len(ip_data) >= 20:
                                proto_num = ip_data[9]
                                src_ip = socket.inet_ntoa(ip_data[12:16])
                                dst_ip = socket.inet_ntoa(ip_data[16:20])
                                ihl = (ip_data[0] & 0x0f) * 4
                                proto = 'TCP' if proto_num == 6 else ('UDP' if proto_num == 17 else ('ICMP' if proto_num == 1 else 'OTHER'))
                                
                                sport, dport, flags = None, None, None
                                if proto == 'TCP' and len(ip_data) >= ihl + 14:
                                    tcp_hdr = ip_data[ihl:]
                                    sport, dport = struct.unpack('!HH', tcp_hdr[:4])
                                    flag_byte = tcp_hdr[13]
                                    flag_names = []
                                    if flag_byte & 0x02: flag_names.append('SYN')
                                    if flag_byte & 0x10: flag_names.append('ACK')
                                    if flag_byte & 0x01: flag_names.append('FIN')
                                    if flag_byte & 0x04: flag_names.append('RST')
                                    if flag_byte & 0x08: flag_names.append('PSH')
                                    flags = ",".join(flag_names)
                                elif proto == 'UDP' and len(ip_data) >= ihl + 4:
                                    udp_hdr = ip_data[ihl:]
                                    sport, dport = struct.unpack('!HH', udp_hdr[:4])

                                packets.append({
                                    'source_ip': src_ip,
                                    'dest_ip': dst_ip,
                                    'source_port': sport,
                                    'dest_port': dport,
                                    'protocol': proto,
                                    'packet_size': orig_len,
                                    'tcp_flags': flags,
                                    'traffic_direction': 'INBOUND',
                                    'payload_preview': 'Binary packet frame',
                                    'timestamp': datetime.fromtimestamp(ts_sec).strftime('%Y-%m-%d %H:%M:%S')
                                })
                                pkt_count += 1
            logger.info(f"Binary PCAP reader parsed {len(packets)} packets from {filepath}")
        except Exception as e:
            logger.error(f"Failed to parse binary PCAP: {e}")
        return packets
