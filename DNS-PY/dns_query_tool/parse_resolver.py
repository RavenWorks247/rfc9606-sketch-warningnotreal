import logging
from typing import Dict, Any, List

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
            # Remove the '#' symbol and any extraneous whitespace
            record = record.strip().lstrip('#').strip()

            # Remove any non-hex characters (spaces, etc.) from the string before decoding
            cleaned_record = ''.join(filter(str.isalnum, record))

            # Ensure the cleaned record is a valid hexadecimal string
            if len(cleaned_record) % 2 != 0:
                logging.error("Cleaned record has an odd number of characters and is not valid hex.")
                return {}

            # Decode hex data to ASCII text
            decoded_record = bytearray.fromhex(cleaned_record).decode('utf-8')

            logging.getLogger('dns_query_tool').info(f"Decoded record: {decoded_record}")
            
            # Explicitly check for 'qnamemin'
            if "qnamemin" in decoded_record:
                logging.getLogger('dns_query_tool').info("Found 'qnamemin' in the decoded record.")
                parsed_data['qname_minimization'] = True
            else:
                logging.getLogger('dns_query_tool').info("'qnamemin' not found in the decoded record.")

            # Split attributes by '*' (adjusting split logic)
            attributes = decoded_record.split('*')
            
            for attribute in attributes:
                attribute = attribute.strip()
                logging.getLogger('dns_query_tool').info(f"Processing attribute: {attribute}")
                
                if attribute.startswith("exterr="):
                    # Extract extended error range and process it
                    error_range = attribute.split("=")[1]
                    logging.getLogger('dns_query_tool').info(f"Extended error range found: {error_range}")
                    # Force extended error range parsing
                    extended_error = parse_extended_error_range(error_range)
                    logging.getLogger('dns_query_tool').info(f"Parsed extended error: {extended_error}")
                    parsed_data['extended_errors'] = extended_error
                elif attribute.startswith("infourl="):
                    # Extract info URL
                    parsed_data['info_url'] = attribute.split("=")[1]
    
        # Log the parsed data for verification
        logging.getLogger('dns_query_tool').info(f"Parsed data: {parsed_data}")
    
    except Exception as e:
        logging.error(f"Error parsing RESINFO response: {str(e)}")

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

    # Error codes and their meanings
    error_meanings = {
        15: "DNS query timeout",
        16: "DNS resolution failure",
        17: "DNS server misconfiguration",
    }

    # Split the error range into individual codes
    errors = error_range.split('-')
    error_messages = []

    for code in errors:
        try:
            code = int(code)
            if code in error_meanings:
                error_messages.append(f"Error {code}: {error_meanings[code]}")
            else:
                error_messages.append(f"Unknown error code: {code}")
        except ValueError:
            logging.error(f"Invalid error code in range: {code}")
            error_messages.append(f"Invalid error code: {code}")
    
    if not error_messages:
        return "No extended errors"
    
    # Return all the error messages as a string
    return "; ".join(error_messages)
