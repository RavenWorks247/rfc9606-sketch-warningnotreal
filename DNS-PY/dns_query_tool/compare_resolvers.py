from typing import Dict
from tabulate import tabulate

def compare_resolver_features(resolver_data: Dict[str, Dict]) -> str:
    """
    Compare features between multiple resolvers and format the output.
    
    Args:
        resolver_data (Dict[str, Dict]): Dictionary of resolver data
        
    Returns:
        str: Formatted comparison table
    """
    if not resolver_data:
        return "No resolver data available for comparison."

    # Define features to compare with custom formatting
    features = [
        {
            'name': 'QNAME Minimization', 
            'key': 'qname_minimization', 
            'formatter': lambda x: 'Enabled' if x else 'Disabled',
            'default': 'Not Detected'
        },
        {
            'name': 'Extended Errors', 
            'key': 'extended_errors', 
            'formatter': lambda x: str(x) if x else 'None',
            'default': 'Not Available'
        },
        {
            'name': 'Info URL', 
            'key': 'info_url', 
            'formatter': lambda x: x if x else 'N/A',
            'default': 'No URL'
        }
    ]

    # Prepare the table data
    table_data = []
    
    # Iterate through features
    for feature in features:
        row = [feature['name']]
        
        # Iterate through all resolvers
        for resolver, data in resolver_data.items():
            # Get the value for this feature, use default if not found
            value = data.get(feature['key'])
            formatted_value = feature['formatter'](value) if value is not None else feature['default']
            row.append(formatted_value)
        
        table_data.append(row)

    # Prepare headers (first column is feature name, rest are resolver IPs)
    headers = ['Feature'] + list(resolver_data.keys())

    # Generate table with improved formatting
    return tabulate(
        table_data, 
        headers=headers, 
        tablefmt='fancy_grid',  # More visually appealing format
        numalign='left',
        stralign='left'
    )