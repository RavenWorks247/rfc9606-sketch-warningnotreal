import argparse
import ipaddress
from typing import List
import logging

from query_dns import query_resolver_info
from parse_resolver import parse_dns_response
from compare_resolvers import compare_resolver_features
from utils.helper_functions import format_json_output

def setup_logging():
    """
    Configure logging for the script.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def validate_ip(ip_str: str) -> bool:
    """
    Validate if the provided string is a valid IP address.
    
    Args:
        ip_str (str): IP address to validate
    
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def main():
    # Configure logging
    setup_logging()
    logger = logging.getLogger(__name__)

    # Create argument parser
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
        help='Domain to query for RESINFO records (default: example.com)'
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
        logger.error("No valid resolver IP addresses provided.")
        return
    
    # Store resolver data
    resolver_data = {}
    
    # Query each resolver
    for resolver_ip in valid_resolvers:
        logger.info(f"Querying resolver: {resolver_ip}")
        
        try:
            # Query the resolver
            response = query_resolver_info(resolver_ip, domain=args.domain)
            
            # Parse the response if not None
            if response:
                parsed_data = parse_dns_response(response)
                resolver_data[resolver_ip] = parsed_data
            else:
                logger.warning(f"No data retrieved for resolver {resolver_ip}")
        
        except Exception as e:
            logger.error(f"Error querying resolver {resolver_ip}: {e}")
    
    # Display results
    if resolver_data:
        if args.output == 'json':
            print(format_json_output(resolver_data))
        else:
            comparison = compare_resolver_features(resolver_data)
            print("\nDNS Resolver Capability Comparison:")
            print(comparison)
    else:
        logger.warning("No resolver data available for comparison.")

if __name__ == "__main__":
    main()