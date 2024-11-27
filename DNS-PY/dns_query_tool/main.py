import argparse
import ipaddress
from typing import List
from query_dns import query_resolver_info
from parse_resolver import parse_dns_response
from compare_resolvers import compare_resolver_features
from utils.helper_functions import format_json_output

def validate_ip(ip_str: str) -> bool:
    """
    Validate if the provided string is a valid IP address.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Query and compare DNS resolver information based on RESINFO records'
    )
    parser.add_argument(
        'resolvers', 
        nargs='+', 
        help='IP addresses of DNS resolvers to query'
    )
    parser.add_argument(
        '--domain', 
        default='example.com', 
        help='Domain to query for RESINFO records (default: maoi.in)'
    )
    parser.add_argument(
        '--output', 
        choices=['table', 'json'], 
        default='table', 
        help='Output format (default: table)'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate resolver IP addresses
    valid_resolvers = [ip for ip in args.resolvers if validate_ip(ip)]
    
    if not valid_resolvers:
        print("Error: No valid resolver IP addresses provided.")
        return
    
    # Store resolver data
    resolver_data = {}
    
    # Query each resolver
    for resolver_ip in valid_resolvers:
        print(f"Querying resolver: {resolver_ip}")
        
        # Query the resolver
        try:
            response = query_resolver_info(resolver_ip, domain=args.domain)
            
            # Parse the response if not None
            if response:
                parsed_data = parse_dns_response(response)
                resolver_data[resolver_ip] = parsed_data
            else:
                print(f"No data retrieved for resolver {resolver_ip}")
        
        except Exception as e:
            print(f"Error querying resolver {resolver_ip}: {e}")
    
    # Display results
    if resolver_data:
        if args.output == 'json':
            print(format_json_output(resolver_data))
        else:
            comparison = compare_resolver_features(resolver_data)
            print("\nDNS Resolver Capability Comparison:")
            print(comparison)
    else:
        print("No resolver data available for comparison.")

if __name__ == "__main__":
    main()