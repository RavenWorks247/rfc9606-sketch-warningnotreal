from typing import Dict, List
from tabulate import tabulate

def compare_resolver_features(resolver_data: Dict[str, Dict]) -> str:
    """
    Compare features between multiple resolvers and format the output
    
    Args:
        resolver_data (Dict[str, Dict]): Dictionary of resolver data
        
    Returns:
        str: Formatted comparison table
    """
    if not resolver_data:
        return "No resolver data available for comparison"
        
    headers = ['Feature'] + list(resolver_data.keys())
    comparison_rows = []
    
    # Get all unique features across resolvers
    all_features = set()
    for resolver_info in resolver_data.values():
        all_features.update(resolver_info.keys())
    
    # Build comparison table
    for feature in sorted(all_features):
        row = [feature]
        for resolver in resolver_data.keys():
            value = resolver_data[resolver].get(feature, 'N/A')
            if isinstance(value, bool):
                row.append('✓' if value else '✗')
            elif isinstance(value, (dict, list)):
                row.append(str(value))
            else:
                row.append(str(value))
        comparison_rows.append(row)
    
    return tabulate(comparison_rows, headers=headers, tablefmt='grid')