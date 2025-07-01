# modbus_scanner/utils/network_utils.py
"""
Network-related utility functions, like IP address parsing.
"""
import ipaddress
import logging
from typing import List, Set

logger = logging.getLogger("rich")

def parse_ip_targets(target_str: str) -> List[str]:
    """
    Parses a target string into a list of individual IP addresses.
    The string can be a single IP, an IP range (e.g., "192.168.1.1-100"),
    or a CIDR block (e.g., "192.168.1.0/24").
    It can also be a comma-separated list of these.

    :param target_str: The target string to parse.
    :return: A sorted list of unique IP address strings.
    """
    if not target_str:
        return []

    all_ips: Set[str] = set()
    parts = target_str.split(',')

    for part in parts:
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part: # Potential IP Range
                start_ip_str, end_range_str = part.split('-', 1)
                start_ip = ipaddress.ip_address(start_ip_str)
                end_ip_str_to_parse = end_range_str # Default to using end_range_str as is for full IPs

                is_ipv4_suffix_range = start_ip.version == 4 and '.' not in end_range_str and end_range_str.isdigit()

                if is_ipv4_suffix_range:
                    start_octets = start_ip_str.split('.')
                    # This check is implicitly handled by ipaddress.ip_address(start_ip_str) succeeding
                    # if len(start_octets) != 4:
                    #      raise ValueError(f"Invalid start IP for IPv4 range suffix: {start_ip_str}")
                    if not (0 <= int(end_range_str) <= 255):
                        logger.warning(f"Invalid end range suffix '{end_range_str}' for IPv4 range '{part}'. Must be 0-255. Skipping.")
                        continue
                    end_ip_str_to_parse = f"{start_octets[0]}.{start_octets[1]}.{start_octets[2]}.{end_range_str}"
                elif start_ip.version == 6 and ':' not in end_range_str:
                    # IPv6 with non-full end_range_str (suffix) is not supported
                    logger.warning(f"Short-form range suffix ('{end_range_str}') for IPv6 range ('{part}') is not supported. Use full IPs or CIDR. Skipping.")
                    continue

                end_ip = ipaddress.ip_address(end_ip_str_to_parse)

                if start_ip.version != end_ip.version:
                    logger.warning(f"IP range '{part}' has different IP versions after parsing. Start: {start_ip.version}, End: {end_ip.version}. Skipping.")
                    continue
                if end_ip < start_ip:
                    logger.warning(f"End IP '{end_ip}' is less than start IP '{start_ip}' in range '{part}'. Skipping.")
                    continue

                current_ip_int = int(start_ip)
                end_ip_int = int(end_ip)
                while current_ip_int <= end_ip_int:
                    all_ips.add(str(ipaddress.ip_address(current_ip_int)))
                    current_ip_int += 1

            elif '/' in part: # Potential CIDR
                net = ipaddress.ip_network(part, strict=False) # strict=False allows host bits to be set
                for ip in net.hosts(): # .hosts() for networks, or just the net.network_address if it's a single host CIDR /32 or /128
                    all_ips.add(str(ip))
                # If it's like 192.168.1.1/32, .hosts() is empty. Add the network_address itself.
                # For larger networks, .network_address and .broadcast_address are usually not scanned as targets themselves unless specified.
                # The prompt implies scanning devices, so .hosts() is generally correct.
                # However, some might want to scan the .network_address too if it could be a device.
                # For simplicity now, .hosts() is fine. If a /32 or /128 is given, ip_network will represent that single address.
                # Let's clarify behavior for /32 and /128
                if net.num_addresses == 1: # For /32 IPv4 or /128 IPv6
                    all_ips.add(str(net.network_address))


            else: # Single IP
                ip = ipaddress.ip_address(part)
                all_ips.add(str(ip))
        except ValueError as e:
            logger.warning(f"Invalid IP target format '{part}': {e}. Skipping this part.")
            continue
        except Exception as e:
            logger.error(f"Unexpected error parsing IP target part '{part}': {e}. Skipping this part.")
            continue

    return sorted(list(all_ips), key=ipaddress.ip_address)
