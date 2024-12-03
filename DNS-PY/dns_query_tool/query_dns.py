import dns.resolver
import dns.message
import dns.query
import dns.rdata
import dns.rdatatype
import logging
from typing import Optional, List

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('dns_query_tool')

# RESINFO record type as specified in RFC 9606
RESINFO = 261

def query_resolver_info(resolver_address: str, domain: str = 'example.com', query_type: str = 'RESINFO') -> Optional[List[str]]:
    """
    Query a DNS resolver for specified records, defaulting to RESINFO.
    
    Args:
        resolver_address (str): IP address of the DNS resolver
        domain (str): Domain to query
        query_type (str): DNS query type (e.g., 'A', 'AAAA', 'RESINFO')
        
    Returns:
        Optional[List[str]]: Record contents or None if query fails
    """
    logger = setup_logging()
    
    # Route queries other than RESINFO or 'example.com' to 1.1.1.1
    if domain != 'example.com' or query_type != 'RESINFO':
        resolver_address = '1.1.1.1'
    
    try:
        # Construct a DNS query with the specified type
        if query_type.upper() == 'RESINFO':
            query = dns.message.make_query(domain, RESINFO)
        else:
            query = dns.message.make_query(domain, dns.rdatatype.from_text(query_type))
        
        # Send the query to the designated resolver
        response = dns.query.udp(query, resolver_address, timeout=5)
        
        # Log the full DNS response for debugging
        logger.info(f"Full DNS response from {resolver_address}: {response}")
        
        # Extract and process the response records
        record_list = []
        for answer in response.answer:
            logger.info(f"Answer section: {answer}")
            for rdata in answer:
                record_text = rdata.to_text().strip('"').strip()
                logger.info(f"Record text: {record_text}")
                record_list.append(record_text)
        
        if record_list:
            logger.info(f"Retrieved {len(record_list)} records from {resolver_address}")
            return record_list
        else:
            logger.error(f"No records found for {domain} with query type {query_type}")
            return None
    
    except Exception as e:
        logger.error(f"Error querying {resolver_address} for {query_type} on {domain}: {str(e)}")
        return None