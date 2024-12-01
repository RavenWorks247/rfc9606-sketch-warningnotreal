from flask import Flask, request, jsonify, render_template
import ipaddress
import logging
from query_dns import query_resolver_info
from parse_resolver import parse_dns_response
from compare_resolvers import compare_resolver_features
from utils.helper_functions import format_json_output

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def validate_ip(ip_str: str) -> bool:
    """
    Validate if the provided string is a valid IP address.
    
    Args:
        ip_str (str): IP address to validate
    
    Returns:
        bool: True if valid IP, False otherwise
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
def query():
    try:
        # Extract and parse resolvers
        resolvers_input = request.form.get('resolvers', '')
        resolvers = [ip.strip() for ip in resolvers_input.split(',') if ip.strip()]
        domain = request.form.get('domain', 'example.com')
        output_format = request.form.get('output', 'table')
        
        # Log parsed resolvers
        logger.info(f"Parsed resolvers: {resolvers}")

        # Validate resolver IPs
        valid_resolvers = [ip for ip in resolvers if validate_ip(ip)]
        logger.info(f"Valid resolvers: {valid_resolvers}")

        if not valid_resolvers:
            return jsonify({"error": "No valid resolver IP addresses provided."}), 400
        
        # Query each resolver
        resolver_data = {}
        for resolver_ip in valid_resolvers:
            logger.info(f"Querying resolver: {resolver_ip}")
            try:
                response = query_resolver_info(resolver_ip, domain=domain)
                if response:
                    parsed_data = parse_dns_response(response)
                    resolver_data[resolver_ip] = parsed_data
                else:
                    logger.warning(f"No data retrieved for resolver {resolver_ip}")
            except Exception as e:
                logger.error(f"Error querying resolver {resolver_ip}: {e}")
        
        # Format results
        if resolver_data:
            if output_format == 'json':
                return jsonify(resolver_data)
            else:
                comparison = compare_resolver_features(resolver_data)
                return render_template('result.html', comparison=comparison)
        else:
            return jsonify({"warning": "No resolver data available for comparison."}), 200
    
    except Exception as e:
        logger.error(f"Error processing query: {e}")
        return jsonify({"error": "An internal error occurred."}), 500


if __name__ == '__main__':
    app.run(debug=True)
