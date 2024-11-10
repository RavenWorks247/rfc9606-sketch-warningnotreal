import dns.resolver
import json
import logging
from typing import Dict, Any

def parse_dns_response(response: dns.resolver.Answer) -> Dict[str, Any]:
    """
    Parse DNS resolver response into structured data
    
    Args:
        response (dns.resolver.Answer): DNS response from resolver
        
    Returns:
        Dict[str, Any]: Parsed resolver capabilities and features
    """
    if not response:
        return {}
        
    parsed_data = {
        'dnssec_support': False,
        'qname_minimization': False,
        'caching_enabled': False,
        'filtering_enabled': False,
        'privacy_policy': {},
        'supported_features': []
    }
    
    try:
        for rdata in response:
            # RFC 9606 specifies TXT record format
            txt_data = rdata.strings[0].decode('utf-8')
            resolver_info = json.loads(txt_data)
            
            parsed_data.update({
                'dnssec_support': resolver_info.get('dnssec', False),
                'qname_minimization': resolver_info.get('qname_min', False),
                'caching_enabled': resolver_info.get('cache', False),
                'filtering_enabled': resolver_info.get('filtering', False),
                'privacy_policy': resolver_info.get('privacy', {}),
                'supported_features': resolver_info.get('features', [])
            })
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logging.error(f"Error parsing resolver response: {str(e)}")
    
    return parsed_data