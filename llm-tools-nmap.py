import llm
import subprocess
import shlex
import socket
import re
import ipaddress # Added for reliable IP/Netmask handling

def hex_to_dot_decimal(hex_mask):
    """Convert hexadecimal netmask (e.g., '0xff000000') to dot-decimal (e.g., '255.0.0.0')."""
    # Remove '0x' prefix if present and ensure it's 8 characters (32 bits)
    hex_mask = hex_mask.lstrip('0x').zfill(8)
    
    # Split into 4 bytes (2 hex characters each) and convert to decimal
    try:
        octets = []
        for i in range(0, 8, 2):
            octet = int(hex_mask[i:i+2], 16)
            octets.append(str(octet))
        return '.'.join(octets)
    except Exception:
        return None

def get_local_network_info():
    """
    Get local network information including IP addresses, subnet masks, and network ranges for scanning.
    
    Returns:
        A string containing local IP addresses, subnet information, and suggested scan ranges
    """
    try:
        # Get hostname
        hostname = socket.gethostname()
        
        # Method 1: Get IP by connecting to a public DNS server
        primary_ip = "Unable to determine"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to Google's public DNS server
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
        except:
            pass
        
        # Method 2: Get all IPs associated with hostname
        try:
            all_ips = socket.gethostbyname_ex(hostname)[2]
        except:
            all_ips = []
        
        # Try to get network interface information using ip command (Linux/macOS)
        interface_info = []
        scan_ranges = []
        
        try:
            result = subprocess.run(
                ["ip", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse output for interface names and IPs
                current_interface = None
                for line in result.stdout.split('\n'):
                    # Match interface line
                    if re.match(r'^\d+:', line):
                        current_interface = line.split(':')[1].strip()
                    # Match inet line
                    elif 'inet ' in line and current_interface:
                        # Linux 'ip addr' typically uses CIDR notation
                        ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                        if ip_match and not ip_match.group(1).startswith('127.'):
                            ip_addr = ip_match.group(1)
                            cidr = ip_match.group(2)
                            interface_info.append(f"{current_interface}: {ip_addr}/{cidr}")
                            
                            # Calculate network range
                            network_range = calculate_network_range(ip_addr, cidr)
                            if network_range and network_range not in scan_ranges:
                                scan_ranges.append(network_range)
        except:
            # If ip command fails, try ifconfig
            try:
                result = subprocess.run(
                    ["ifconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Parse ifconfig output for interfaces
                    current_interface = None
                    lines = result.stdout.split('\n')
                    
                    for i, line in enumerate(lines):
                        # Detect interface name (starts at beginning of line)
                        if line and not line.startswith(' ') and not line.startswith('\t'):
                            current_interface = line.split()[0].rstrip(':')
                        
                        # Look for inet lines
                        if 'inet ' in line and current_interface:
                            # Extract IP and look for netmask in dot-decimal OR hexadecimal format
                            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                            
                            if ip_match and not ip_match.group(1).startswith('127.'):
                                ip_addr = ip_match.group(1)
                                netmask = None
                                cidr = None
                                
                                # 1. Try to find dot-decimal netmask (Linux/BSD style)
                                netmask_match = re.search(r'netmask (\d+\.\d+\.\d+\.\d+)', line)
                                if netmask_match:
                                    netmask = netmask_match.group(1)
                                    cidr = netmask_to_cidr(netmask)
                                
                                # 2. Try to find hexadecimal netmask (macOS style)
                                if not netmask:
                                    hex_netmask_match = re.search(r'netmask (0x[0-9a-fA-F]{8})', line)
                                    if hex_netmask_match:
                                        # Convert hex to dot-decimal
                                        netmask = hex_to_dot_decimal(hex_netmask_match.group(1))
                                        if netmask:
                                            cidr = netmask_to_cidr(netmask)
                                
                                # Process if we found both IP and CIDR
                                if netmask and cidr is not None:
                                    interface_info.append(f"{current_interface}: {ip_addr}/{cidr}")
                                    
                                    # Calculate network range
                                    # CIDR is the *integer* returned from netmask_to_cidr
                                    network_range = calculate_network_range(ip_addr, str(cidr)) 
                                    if network_range and network_range not in scan_ranges:
                                        scan_ranges.append(network_range)
                                else:
                                    interface_info.append(f"{current_interface}: {ip_addr} (Netmask not found or unconvertible)")
            except:
                pass
        
        # Build response
        response = f"Hostname: {hostname}\n"
        response += f"Primary IP: {primary_ip}\n"
        
        if all_ips:
            response += f"All IPs for hostname: {', '.join(all_ips)}\n"
        
        if interface_info:
            response += "\nNetwork interfaces:\n"
            for info in interface_info:
                response += f"  {info}\n"
        
        if scan_ranges:
            response += "\nNetwork ranges (for scanning):\n"
            for range_info in scan_ranges:
                response += f"  {range_info}\n"
        else:
            # Fallback: suggest /24 network if we have a primary IP
            if primary_ip != "Unable to determine":
                octets = primary_ip.split('.')
                if len(octets) == 4:
                    network_base = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                    response += f"\nSuggested scan range (assuming /24): {network_base}\n"
        
        # Add helpful note
        response += "\nNote: Use the network ranges above with nmap_ping_scan to discover all devices."
        
        return response
        
    except Exception as ex:
        return f"Error getting network info: {type(ex).__name__}: {ex}"


def calculate_network_range(ip_addr, cidr):
    """Calculate network range from IP and CIDR notation (Simplified using ipaddress)"""
    try:
        # Use ipaddress module for reliable calculation
        network = ipaddress.ip_network(f'{ip_addr}/{cidr}', strict=False)
        return str(network)
    except:
        # Fallback to original calculation if ipaddress is unavailable or fails
        try:
            cidr_int = int(cidr)
            # Calculate network address
            ip_parts = [int(x) for x in ip_addr.split('.')]
            
            # Calculate host bits
            host_bits = 32 - cidr_int
            
            # Create subnet mask
            mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
            
            # Calculate network address
            network_addr = []
            for i in range(4):
                network_addr.append(ip_parts[i] & ((mask >> (24 - i * 8)) & 0xFF))
            
            network_str = '.'.join(map(str, network_addr))
            return f"{network_str}/{cidr}"
        except:
            return None


def netmask_to_cidr(netmask):
    """Convert dot-decimal netmask to CIDR notation"""
    try:
        # Check for valid dot-decimal format
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', netmask):
            return 24 # Fallback if format is not dot-decimal

        # Convert netmask to binary and count the 1s
        parts = netmask.split('.')
        binary = ''.join([bin(int(part))[2:].zfill(8) for part in parts])
        
        # The CIDR is the count of leading '1's
        return binary.count('1')
    except:
        return 24  # Default to /24

# The rest of your functions (nmap_scan, nmap_quick_scan, etc.) remain unchanged.
# ... (nmap_scan, nmap_quick_scan, nmap_port_scan, nmap_service_detection, 
# nmap_os_detection, nmap_ping_scan, nmap_script_scan, register_tools)
# ...

# --- Unchanged Nmap functions for completeness (omitted for brevity in response) ---
def nmap_scan(target, options=""):
    """
    Run an Nmap scan on the specified target with optional parameters.
    """
    cmd_parts = ["nmap"]
    if options:
        cmd_parts.extend(shlex.split(options))
    cmd_parts.append(target)
    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )
        if result.returncode != 0:
            return f"Error: Nmap returned non-zero exit code {result.returncode}\nStderr: {result.stderr}"
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Error: Nmap scan timed out after 5 minutes"
    except FileNotFoundError:
        return "Error: nmap command not found. Please install nmap first."
    except Exception as ex:
        return f"Error: {type(ex).__name__}: {ex}"

def nmap_quick_scan(target):
    return nmap_scan(target, "-T4 -F")

def nmap_port_scan(target, ports):
    return nmap_scan(target, f"-p {ports}")

def nmap_service_detection(target, ports=""):
    options = "-sV"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)

def nmap_os_detection(target):
    return nmap_scan(target, "-O")

def nmap_ping_scan(target):
    return nmap_scan(target, "-sn")

def nmap_script_scan(target, script, ports=""):
    options = f"--script {script}"
    if ports:
        options += f" -p {ports}"
    return nmap_scan(target, options)

@llm.hookimpl
def register_tools(register_nmap):
    # Register each function as a separate tool
    register_nmap(get_local_network_info)
    register_nmap(nmap_scan)
    register_nmap(nmap_quick_scan)
    register_nmap(nmap_port_scan)
    register_nmap(nmap_service_detection)
    register_nmap(nmap_os_detection)
    register_nmap(nmap_ping_scan)
    register_nmap(nmap_script_scan)
