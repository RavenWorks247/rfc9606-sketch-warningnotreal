import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import logging
import re
import binascii
from typing import Optional, List, Dict, Union, Any

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('dns_query_tool')

# RESINFO record type as specified in RFC 9606
RESINFO = 261

def parse_resinfo_record(record: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Decode and parse a RESINFO record with robust handling of different input types.
    
    Args:
        record: Raw RESINFO record as text or a dictionary
    
    Returns:
        Dict[str, Any]: Parsed RESINFO record information
    """
    logger = setup_logging()
    
    try:
        # If input is already a dictionary, return it directly
        if isinstance(record, dict):
            return record
        
        # If input is a string
        if isinstance(record, str):
            # Handle hex-encoded record starting with \#
            if record.startswith('\\# '):
                try:
                    # Extract hex data and remove spaces
                    hex_parts = record.split('\\#')[1].split()
                    hex_data = ''.join(hex_parts[1:])
                    
                    # Decode hex to string
                    decoded_record = bytes.fromhex(hex_data).decode('utf-8', errors='ignore')
                    logger.info(f"Decoded RESINFO record: {decoded_record}")
                except (ValueError, binascii.Error) as hex_error:
                    logger.error(f"Hex decoding error: {hex_error}")
                    return {}
            else:
                decoded_record = record

            # Parse QNAME Minimization
            result = {
                'qnamemin': 'qnamemin' in decoded_record,
                'exterr': None,
                'infourl': None
            }

            # Parse Extended Errors
            exterr_match = re.search(r'exterr=([0-9-]+)', decoded_record)
            if exterr_match:
                result['exterr'] = exterr_match.group(1)

            # Parse Info URL
            infourl_match = re.search(r'infourl=([^\s*]+)', decoded_record)
            if infourl_match:
                result['infourl'] = infourl_match.group(1)

            logger.info(f"Parsed RESINFO record: {result}")
            return result

        logger.warning("Unprocessable RESINFO record type")
        return {}

    except Exception as e:
        logger.error(f"Unexpected error parsing RESINFO record: {e}")
        return {}

def query_resolver_info(resolver_address: str, domain: str = 'example.com', query_type: str = 'A') -> Optional[List[str]]:
    """
    Query a DNS resolver for specified record types.
    
    Args:
        resolver_address (str): IP address of the DNS resolver
        domain (str): Domain to query
        query_type (str): Type of DNS record to query (A, AAAA, RESINFO, etc.)
        
    Returns:
        Optional[List[str]]: List of record values or parsed RESINFO records
    """
    logger = setup_logging()
    
    try:
        # For RESINFO, use the existing special handling
        if query_type == 'RESINFO':
            return query_resolver_info_special(resolver_address)
        
        # Convert query type to DNS record type
        record_type = getattr(dns.rdatatype, query_type)
        
        # Create DNS query
        query = dns.message.make_query(domain, record_type)
        logger.info(f"Sending {query_type} query to {resolver_address} for domain {domain}...")
        
        # Send the query
        response = dns.query.udp(query, resolver_address, timeout=5)
        logger.info(f"Received DNS response for {query_type}")

        # Extract and return record values
        records = []
        for answer in response.answer:
            for rdata in answer:
                # Convert record to string representation
                records.append(rdata.to_text())
        
        if records:
            logger.info(f"Retrieved {len(records)} {query_type} records")
            return records
        else:
            logger.warning(f"No {query_type} records found for domain {domain}")
            return None
    
    except Exception as e:
        logger.error(f"Error querying {resolver_address} for {query_type}: {str(e)}")
        return None

def query_resolver_info_special(resolver_address: str) -> Optional[List[Dict[str, Any]]]:
    """
    Special handler for RESINFO queries.
    
    Args:
        resolver_address (str): IP address of the DNS resolver
        
    Returns:
        Optional[List[Dict[str, Any]]]: Parsed RESINFO records
    """
    logger = setup_logging()
    
    try:
        # Construct a DNS query for the RESINFO type
        query = dns.message.make_query('example.com', RESINFO)
        logger.info(f"Sending RESINFO query to {resolver_address}...")
        
        # Send the query
        response = dns.query.udp(query, resolver_address, timeout=5)
        logger.info(f"Received DNS response: {response}")

        resinfo_records = []
        for answer in response.answer:
            logger.info(f"Processing answer: {answer}")
            for rdata in answer:
                raw_text = rdata.to_text()
                logger.info(f"Raw RESINFO record: {raw_text}")
                parsed_record = parse_resinfo_record(raw_text)
                resinfo_records.append(parsed_record)
        
        if resinfo_records:
            logger.info(f"Retrieved {len(resinfo_records)} RESINFO records")
            return resinfo_records
        else:
            logger.warning("No RESINFO records found")
            return None
    
    except Exception as e:
        logger.error(f"Error querying {resolver_address} for RESINFO: {str(e)}")
        return None