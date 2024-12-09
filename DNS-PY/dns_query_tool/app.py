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
                
                # Call query_resolver_info with correct parameters
                response = query_resolver_info(resolver_ip, domain, query_type)

                # Process different query types
                if query_type == 'RESINFO' and response:
                    resinfo_result = {
                        'QNAME Minimization': 'Yes' if response[0].get('qnamemin', False) else 'No',
                        'Extended Errors': response[0].get('exterr', 'No extended errors'),
                        'Info URL': response[0].get('infourl', 'No info URL')
                    }
                    query_results[resolver_ip][query_type] = resinfo_result
                elif response:
                    # For other record types, join the records
                    query_results[resolver_ip][query_type] = ', '.join(response)
                else:
                    query_results[resolver_ip][query_type] = "No data"

        if output_format == 'json':
            return jsonify(query_results)
        else:
            # Generate a comprehensive table format
            table_data = []
            
            # Prepare headers with resolver IPs
            headers = ['Feature/Record Type'] + list(query_results.keys())
            
            # RESINFO-specific features
            resinfo_features = ['QNAME Minimization', 'Extended Errors', 'Info URL']
            
            # Add RESINFO features to table
            for feature in resinfo_features:
                row = [feature]
                for resolver_ip in query_results:
                    # Extract RESINFO feature or use 'N/A'
                    resinfo = query_results[resolver_ip].get('RESINFO', {})
                    value = resinfo.get(feature, 'N/A') if isinstance(resinfo, dict) else 'N/A'
                    row.append(value)
                table_data.append(row)

            # Add non-RESINFO record types
            for query_type in query_types:
                if query_type != 'RESINFO':
                    row = [query_type]
                    for resolver_ip in query_results:
                        # Get record type value or use 'No data'
                        row.append(query_results[resolver_ip].get(query_type, 'No data'))
                    table_data.append(row)
            
            # Generate table with HTML format for better rendering
            table_output = tabulate(table_data, headers, tablefmt='html')
            return render_template('result.html', comparison=table_output)
    
    except Exception as e:
        logger.error(f"Error processing query: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred."}), 500

if __name__ == '__main__':
    app.run(debug=True)
