from typing import Any, Dict
import json

def format_json_output(data: Dict[str, Any]) -> str:
    """
    Format dictionary data as pretty-printed JSON
    
    Args:
        data (Dict[str, Any]): Data to format
        
    Returns:
        str: Pretty-printed JSON string
    """
    return json.dumps(data, indent=2, sort_keys=True)

def validate_resolver_info(info: Dict[str, Any]) -> bool:
    """
    Validate resolver information against RFC 9606 requirements
    
    Args:
        info (Dict[str, Any]): Resolver information to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    required_fields = ['dnssec', 'qname_min', 'cache']
    return all(field in info for field in required_fields)