import argparse
from typing import List
import ipaddress
import logging
from query_dns import query_resolver_info
from parse_resolver import parse_dns_response
from compare_resolvers import compare_resolver_features
from utils.helper_functions import format_json_output

def validate_ip(ip_str: str) -> bool:
    """
    Validate if the provided string is a valid IP address
    
    Args:
        ip_str (str): IP address string to validate
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Query and compare DNS resolver information based on RFC 9606'
    )
    parser.add_argument(
        'resolvers',
        nargs='+',
        help='IP addresses of DNS resolvers to query'
    )
    parser.add_argument(
        '--output',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)'
    )
    
    args = parser.parse_args()
    
    # Validate resolver IP addresses
    resolver_ips = [ip for ip in args.resolvers if validate_ip(ip)]
    if not resolver_ips:
        print("Error: No valid resolver IP addresses provided")
        return
    
    # Query and compare resolvers
    resolver_data = {}
    for resolver_ip in resolver_ips:
        print(f"Querying resolver: {resolver_ip}")
        response = query_resolver_info(resolver_ip)
        if response:
            parsed_data = parse_dns_response(response)
            resolver_data[resolver_ip] = parsed_data
    
    # Display comparison
    if resolver_data:
        if args.output == 'json':
            print(format_json_output(resolver_data))
        else:
            comparison = compare_resolver_features(resolver_data)
            print("\nDNS Resolver Capability Comparison:")
            print(comparison)
    else:
        print("No resolver data available for comparison")

if __name__ == "__main__":
    main()