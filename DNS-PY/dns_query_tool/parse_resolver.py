import logging
from typing import Dict, Any, List
import binascii
import re

def parse_dns_response(response: List[str]) -> Dict[str, Any]:
    """
    Parse DNS resolver RESINFO response into structured data.
    
    Args:
        response (List[str]): RESINFO record contents
        
    Returns:
        Dict[str, Any]: Parsed resolver capabilities and features
    """
    if not response:
        logging.error("Empty response provided.")
        return {}

    parsed_data = {
        'qname_minimization': False,
        'extended_errors': None,
        'info_url': None
    }
    
    try:
        # Log the raw response for debugging
        logging.getLogger('dns_query_tool').info(f"Raw RESINFO response: {response}")
        
        # Process each record in the response
        for record in response:
            # Remove the '\#' prefix and whitespace, and remove spaces
            record = record.replace('\\#', '').replace(' ', '')

            try:
                # Decode hex string
                decoded_record = bytes.fromhex(record).decode('utf-8', errors='ignore')
                logging.getLogger('dns_query_tool').info(f"Decoded record: {decoded_record}")
                
                # Check for qname minimization
                if "qnamemin" in decoded_record:
                    parsed_data['qname_minimization'] = True

                # Extract extended errors using regex
                exterr_match = re.search(r'exterr=(\d+(?:-\d+)?)', decoded_record)
                if exterr_match:
                    error_range = exterr_match.group(1)
                    parsed_data['extended_errors'] = parse_extended_error_range(error_range)

                # Extract info URL
                infourl_match = re.search(r'infourl=([^*\s]+)', decoded_record)
                if infourl_match:
                    parsed_data['info_url'] = infourl_match.group(1)
            
            except (ValueError, binascii.Error) as decode_error:
                logging.error(f"Decoding error for record {record}: {str(decode_error)}")
                continue
    
    except Exception as e:
        logging.error(f"Error parsing RESINFO response: {str(e)}")

    # Log the parsed data for verification
    logging.getLogger('dns_query_tool').info(f"Parsed data: {parsed_data}")
    return parsed_data

def parse_extended_error_range(error_range: str) -> str:
    """
    Parse and interpret the extended error range.
    
    Args:
        error_range (str): The extended error range (e.g., '15-17')
        
    Returns:
        str: Human-readable interpretation of the error range.
    """
    logging.getLogger('dns_query_tool').info(f"Parsing extended error range: {error_range}")

    # Expanded error codes and their meanings
    error_meanings = {
        15: "DNS query timeout",
        16: "DNS resolution failure", 
        17: "DNS server misconfiguration",
        18: "Network connectivity issue",
        19: "DNS server unreachable",
        20: "DNSSEC validation failure"
    }

    # Split the error range into individual codes
    try:
        # Support single codes and ranges
        if '-' in error_range:
            start, end = map(int, error_range.split('-'))
            error_codes = range(start, end + 1)
        else:
            error_codes = [int(error_range)]

        # Collect error messages
        error_messages = []
        for code in error_codes:
            if code in error_meanings:
                error_messages.append(f"Error {code}: {error_meanings[code]}")
            else:
                error_messages.append(f"Unknown error code: {code}")
        
        return "; ".join(error_messages) if error_messages else "No extended errors"
    
    except ValueError:
        logging.error(f"Invalid error range format: {error_range}")
        return "Invalid error range"