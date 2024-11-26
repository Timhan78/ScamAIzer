from flask import Flask, request, render_template
from site_checker import is_valid_domain, check_website_with_virustotal, get_whois_info

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    domain = request.form.get('domain').strip()
    if is_valid_domain(domain):
        result = f"'{domain}' is a valid domain name.<br>"
        result += check_website_with_virustotal(domain)
        result += "<br><strong>WHOIS Information:</strong><br>"
        result += get_whois_info(domain)
    else:
        result = f"'{domain}' is not a valid domain name. Please try again."
    return result

if __name__ == "__main__":
    app.run(debug=True)
