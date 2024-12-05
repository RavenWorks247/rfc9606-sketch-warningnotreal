from flask import Flask, request, jsonify, render_template
import ipaddress
import logging
from query_dns import query_resolver_info, parse_resinfo_record
from typing import Union, Dict, List
from tabulate import tabulate

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def validate_ip(ip_str: str) -> bool:
    """
    Validate if the provided string is a valid IP address.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

@app.route('/')
def home():
    """
    Render the home page with a form to input resolver details.
    """
    return render_template('index.html')

@app.route('/query', methods=['POST'])
def query() -> Union[Dict, str]:
    """
    Process DNS query requests from the web form.
    """
    try:
        resolvers_input = request.form.get('resolvers', '')
        domain = request.form.get('domain', 'example.com')
        query_types = [qt.strip().upper() for qt in request.form.get('query_types', 'A,AAAA,RESINFO').split(',')]
        output_format = request.form.get('output', 'table')
        
        resolvers = [ip.strip() for ip in resolvers_input.split(',') if validate_ip(ip.strip())]
        if not resolvers:
            return jsonify({"error": "No valid resolver IP addresses provided."}), 400
        
        query_results = {}

        for resolver_ip in resolvers:
            query_results[resolver_ip] = {}
            for query_type in query_types:
                logger.info(f"Querying {domain} ({query_type}) via {resolver_ip}")
                response = query_resolver_info(resolver_ip, domain, query_type)
                
                # Process different query types
                if query_type == 'RESINFO' and response:
                    # Parse first RESINFO record
                    parsed_resinfo = parse_resinfo_record(response[0]) if response else {}
                    
                    # Map parsed RESINFO to more readable format
                    resinfo_result = {
                        'QNAME Minimization': parsed_resinfo.get('qnamemin', 'Not Supported'),
                        'Extended Errors': parsed_resinfo.get('exterr', 'No extended errors'),
                        'Info URL': parsed_resinfo.get('infourl', 'No info URL')
                    }
                    response = resinfo_result
                elif response:
                    # For other record types, format as a comma-separated string
                    response = ', '.join(map(str, response))
                
                query_results[resolver_ip][query_type] = response or "No data"

        if output_format == 'json':
            return jsonify(query_results)
        else:
            # Comprehensive table generation
            table_data = []
            
            # Prepare headers
            headers = ['Feature/Record Type'] + list(query_results.keys())
            
            # First, add RESINFO features
            default_features = [
                'QNAME Minimization', 
                'Extended Errors', 
                'Info URL'
            ]
            
            # Iterate through default features
            for feature in default_features:
                row = [feature]
                for resolver_ip in query_results.keys():
                    # Extract feature value
                    value = "N/A"
                    for query_type, results in query_results[resolver_ip].items():
                        if isinstance(results, dict) and feature in results:
                            value = str(results[feature])
                            break
                    row.append(value)
                table_data.append(row)
            
            # Add other query types
            other_query_types = [qt for qt in query_types if qt != 'RESINFO']
            for query_type in other_query_types:
                row = [query_type]
                for resolver_ip in query_results.keys():
                    # Get the record values
                    value = query_results[resolver_ip].get(query_type, 'No data')
                    row.append(str(value))
                table_data.append(row)
            
            # Generate table with improved formatting
            table_output = tabulate(
                table_data, 
                headers=headers, 
                tablefmt='html',  # Use HTML format for rendering in template
                numalign='left',
                stralign='left'
            )
            
            return render_template('result.html', comparison=table_output)
    
    except Exception as e:
        logger.error(f"Error processing query: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred."}), 500

if __name__ == '__main__':
    app.run(debug=True)