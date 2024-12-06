import logging
import re
import binascii
from typing import List, Dict, Any

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('dns_query_tool')

def parse_resinfo_record(record_text: str) -> Dict[str, Any]:
    """
    Decode and parse a RESINFO record with robust hex and string handling.
    
    Args:
        record_text (str): Raw RESINFO record text
    
    Returns:
        Dict[str, Any]: Parsed RESINFO record information
    """
    logger = setup_logging()
    
    try:
        # Handle hex-encoded record starting with \#
        if record_text.startswith('\\# '):
            try:
                # Extract hex data and remove spaces
                hex_parts = record_text.split('\\#')[1].split()
                hex_data = ''.join(hex_parts[1:])
                
                # Decode hex to string
                decoded_record = bytes.fromhex(hex_data).decode('utf-8', errors='ignore')
                logger.info(f"Decoded RESINFO record: {decoded_record}")
            except (ValueError, binascii.Error) as hex_error:
                logger.error(f"Hex decoding error: {hex_error}")
                return {}
        else:
            decoded_record = record_text

        # Initialize result dictionary
        result: Dict[str, Any] = {}

        # Parse QNAME Minimization
        result['qname_minimization'] = 'qnamemin' in decoded_record

        # Parse Extended Errors
        exterr_match = re.search(r'exterr=([0-9-]+)', decoded_record)
        if exterr_match:
            result['extended_errors'] = parse_extended_error_range(exterr_match.group(1))

        # Parse Info URL
        infourl_match = re.search(r'infourl=([^\s*]+)', decoded_record)
        if infourl_match:
            result['info_url'] = infourl_match.group(1)

        logger.info(f"Parsed RESINFO record: {result}")
        return result

    except Exception as e:
        logger.error(f"Unexpected error parsing RESINFO record: {e}")
        return {}

def safe_process_query_result(result: Any) -> Dict[str, Any]:
    """
    Safely process query results to ensure consistent dictionary output.
    
    Args:
        result: Raw query result
    
    Returns:
        Dict[str, Any]: Processed and type-safe result
    """
    logger = setup_logging()

    # If result is already a dictionary, ensure safe access
    if isinstance(result, dict):
        return {
            'qname_minimization': result.get('qname_minimization', False),
            'extended_errors': result.get('extended_errors'),
            'info_url': result.get('info_url')
        }
    
    # If result is a string (raw record), parse it
    if isinstance(result, str):
        parsed_result = parse_resinfo_record(result)
        return safe_process_query_result(parsed_result)
    
    # If result is a list, process first item
    if isinstance(result, list) and result:
        return safe_process_query_result(result[0])
    
    logger.warning("Unprocessable query result type")
    return {}