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

def query_resolver_info(resolver_address: str, domain: str = 'example.com') -> Optional[List[str]]:
    """
    Query a DNS resolver for RESINFO records.
    
    Args:
        resolver_address (str): IP address of the DNS resolver
        domain (str): Domain to query RESINFO for
        
    Returns:
        Optional[List[str]]: RESINFO record contents or None if query fails
    """
    logger = setup_logging()
    
    try:
        # Construct a custom DNS query message for RESINFO
        query = dns.message.make_query(domain, RESINFO)
        
        # Send the query directly using dns.query
        response = dns.query.udp(query, resolver_address, timeout=5)
        
        # Log the full response for debugging
        logger.info(f"Full DNS response: {response}")
        
        # Extract RESINFO records
        resinfo_records = []
        for answer in response.answer:
            logger.info(f"Answer section: {answer}")
            for rdata in answer:
                # Convert to text representation
                record_text = rdata.to_text()
                logger.info(f"Raw record text: {record_text}")
                
                # Additional processing to clean up the record
                cleaned_record = record_text.strip('"').strip()
                resinfo_records.append(cleaned_record)
        
        if resinfo_records:
            logger.info(f"Found {len(resinfo_records)} RESINFO records")
            return resinfo_records
        else:
            logger.error(f"No RESINFO records found for {domain}")
            return None
    
    except Exception as e:
        logger.error(f"Error querying resolver {resolver_address} for RESINFO: {str(e)}")
        return None