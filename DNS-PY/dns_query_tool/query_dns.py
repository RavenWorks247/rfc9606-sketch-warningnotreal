import dns.resolver
import dns.message
import dns.query
import logging
from typing import Optional, List, Dict

def setup_logging() -> logging.Logger:
    """
    Set up and configure logging.
    
    Returns:
        logging.Logger: Configured logger instance
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('dns_query_tool')

# RESINFO record type as specified in RFC 9606
RESINFO = 261

def parse_resinfo_record(resinfo_record: str) -> Dict[str, str]:
    """
    Decode and extract key-value pairs from a RESINFO (TYPE261) record.
    
    Args:
        resinfo_record (str): The raw RESINFO record string.
    
    Returns:
        Dict[str, str]: Extracted key-value pairs from the RESINFO record
    """
    logger = logging.getLogger('dns_query_tool')
    
    # Check if it's a hex representation
    if resinfo_record.startswith('\\# '):
        try:
            # Convert hex to bytes
            hex_clean = resinfo_record.replace('\\# ', '').replace(' ', '')
            data = bytes.fromhex(hex_clean)
            
            # Decode the byte data, replacing non-printable characters with spaces
            decoded_data = ''.join([chr(byte) if 32 <= byte <= 126 else ' ' for byte in data])
            decoded_data = decoded_data.replace('*', ' ').strip()
        except (ValueError, TypeError) as e:
            logger.error(f"Error parsing hex RESINFO record: {e}")
            return {}
    else:
        # If not hex-encoded, use the original string
        decoded_data = resinfo_record
    
    # Remove quotes and split into key-value pairs
    cleaned_record = decoded_data.strip('"')
    pairs = [pair.strip('"') for pair in cleaned_record.split('"') if pair.strip()]
    
    # Convert pairs to a dictionary
    result = {}
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            result[key.strip()] = value.strip()
        else:
            # Handle standalone flags like 'qnamemin'
            result[pair.strip()] = 'Supported'
    
    logger.info(f"Parsed RESINFO record: {result}")
    return result

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
                # For RESINFO, parse the record
                if query_type.upper() == 'RESINFO':
                    record_text = rdata.to_text()
                    record_list.append(record_text)
                else:
                    # For other record types, use existing method
                    record_text = rdata.to_text().strip('"').strip()
                    record_list.append(record_text)
                
                logger.info(f"Record text: {record_text}")
        
        if record_list:
            logger.info(f"Retrieved {len(record_list)} records from {resolver_address}")
            return record_list
        else:
            logger.warning(f"No records found for {domain} with query type {query_type}")
            return None
    
    except dns.exception.DNSException as e:
        logger.error(f"DNS query error for {resolver_address} on {domain}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error querying {resolver_address} for {query_type} on {domain}: {str(e)}")
        return None