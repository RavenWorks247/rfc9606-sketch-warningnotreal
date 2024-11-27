from typing import Dict
from tabulate import tabulate

def compare_resolver_features(resolver_data: Dict[str, Dict]) -> str:
    """
    Compare features between multiple resolvers and format the output.
    """
    if not resolver_data:
        return "No resolver data available for comparison."

    headers = ['Feature'] + list(resolver_data.keys())
    comparison_rows = []

    # Define features to compare
    features = ['qname_minimization', 'extended_errors', 'info_url']

    # Build comparison table
    for feature in features:
        row = [feature]
        for resolver in resolver_data.keys():
            value = resolver_data[resolver].get(feature)
            # Format boolean values
            if isinstance(value, bool):
                value = str(value)
            # Replace None with 'N/A' only if truly None
            row.append(value if value is not None else 'N/A')
        comparison_rows.append(row)

    return tabulate(comparison_rows, headers=headers, tablefmt='grid')