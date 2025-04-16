import socket
import struct
import sys

def ethernet_frame(data):
    """Unpacks an Ethernet frame."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

def get_mac_address(bytes_address):
    """Formats MAC address bytes into a readable string."""
    bytes_str = map('{:02x}'.format, bytes_address)
    mac_address = ':'.join(bytes_str).upper()
    return mac_address

def ipv4_packet(data):
    """Unpacks an IPv4 packet."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4_to_str(src), ipv4_to_str(target), data[header_length:]

def ipv4_to_str(address):
    """Converts IPv4 address bytes to a string."""
    return '.'.join(map(str, address))

def tcp_segment(data):
    """Unpacks a TCP segment."""
    (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    """Unpacks a UDP segment."""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def icmp_packet(data):
    """Unpacks an ICMP packet."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def sniff_packets(target_ip=None):
    """Sniffs network packets, optionally filtering by target IP."""
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error as e:
        print(f"Socket creation failed: {e}. You might need to run this with sudo.")
        sys.exit()

    print("[*] Starting network sniffer...")
    if target_ip:
        print(f"[*] Filtering for packets with target IP: {target_ip}")

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"\nEthernet Frame: Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

        # IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, ipv4_data) = ipv4_packet(data)

            # Apply IP filter if target_ip is provided
            if target_ip:
                if target_ip != src and target_ip != target:
                    continue  # Skip packets not involving the target IP

            print(f"  IPv4 Packet: Version: {version}, Header Length: {header_length}, TTL: {ttl}, Protocol: {proto}, Source: {src}, Target: {target}")

            # TCP
            if proto == 6:
                (src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data) = tcp_segment(ipv4_data)
                print(f"    TCP Segment: Source Port: {src_port}, Destination Port: {dest_port}, Sequence: {seq}, Acknowledgment: {ack}")
                # You can further analyze tcp_data here

            # UDP
            elif proto == 17:
                (src_port, dest_port, size, udp_data) = udp_segment(ipv4_data)
                print(f"    UDP Segment: Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}")
                # You can further analyze udp_data here

            # ICMP
            elif proto == 1:
                icmp_type, code, checksum, icmp_data = icmp_packet(ipv4_data)
                print(f"    ICMP Packet: Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                # You can further analyze icmp_data here

        # Other Ethernet protocols can be added here

if __name__ == "__main__":
    target = input("Enter target IP address to filter (leave blank for all traffic): ")
    sniff_packets(target)
    