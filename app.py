from flask import Flask, request, render_template
from site_checker import is_valid_domain, check_website_with_virustotal, get_whois_info
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    domain = request.form.get('domain').strip()
    try:
        if is_valid_domain(domain):
            result = f"'{domain}' is a valid domain name.<br>"
            result += check_website_with_virustotal(domain)
            result += "<br><strong>WHOIS Information:</strong><br>"
            result += get_whois_info(domain)
        else:
            result = f"'{domain}' is not a valid domain name. Please try again."
    except Exception as e:
        result = f"An error occurred: {str(e)}"
    
    # Add a button to return to the homepage
    result += """
    <br><br>
    <form action="/" method="get">
        <button type="submit">Check Another Website</button>
    </form>
    """
    return result

if __name__ == "__main__":
    # Use the port provided by Render or default to 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

