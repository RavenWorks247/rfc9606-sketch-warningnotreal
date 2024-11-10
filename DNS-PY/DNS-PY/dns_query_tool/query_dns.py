import dns.resolver
import dns.exception
import logging
from typing import Optional

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('dns_query_tool')

def query_resolver_info(resolver_address: str, query_type: str = 'TXT') -> Optional[dns.resolver.Answer]:
    """
    Query a DNS resolver for its self-published information based on RFC 9606
    
    Args:
        resolver_address (str): IP address of the DNS resolver
        query_type (str): DNS query type (default: TXT)
        
    Returns:
        Optional[dns.resolver.Answer]: DNS response or None if query fails
    """
    logger = setup_logging()
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolver_address]
    
    try:
        # Query for resolver information as specified in RFC 9606
        response = resolver.resolve('_dns.resolverinfo', query_type)
        return response
    except dns.exception.DNSException as e:
        logger.error(f"DNS query error for {resolver_address}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error querying resolver {resolver_address}: {str(e)}")
        return None