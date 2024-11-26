import re
import requests
import whois  # Импортируем библиотеку WHOIS
from config import API_KEY  # Импортируем ключ

def is_valid_domain(domain):
    # Регулярное выражение для проверки доменных имен
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$"
    return re.match(pattern, domain) is not None

def interpret_reputation(reputation):
    """Интерпретирует числовую репутацию в текст."""
    if reputation >= 4:
        return "Safe"
    elif 0 <= reputation < 4:
        return "Suspicious or needs further review"
    else:
        return "Dangerous"

def check_website_with_virustotal(domain):
    # URL для обращения к VirusTotal API
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": API_KEY
    }
    
    # Отправляем запрос к VirusTotal
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        # Если запрос успешен, возвращаем данные
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        
        # Извлекаем дополнительные данные
        reputation = attributes.get("reputation", "Unknown")
        harmless = attributes.get("last_analysis_stats", {}).get("harmless", 0)
        malicious = attributes.get("last_analysis_stats", {}).get("malicious", 0)
        
        # Интерпретируем репутацию
        reputation_text = interpret_reputation(reputation)
        
        # Формируем строку с результатами
        result = f"""
        Domain: {domain}<br>
        Reputation: {reputation} ({reputation_text})<br>
        Safe detections: {harmless}<br>
        Malicious detections: {malicious}<br>
        """
        if malicious > 0:
            result += "⚠️ Warning: This site might be dangerous!<br>"
        else:
            result += "✅ This site appears to be safe.<br>"
        return result
    else:
        # Если ошибка, возвращаем сообщение
        return f"Error: Unable to fetch data for {domain}. HTTP Status: {response.status_code}<br>"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        result = f"""
        Domain: {domain}<br>
        Registrar: {w.registrar or 'Unknown'}<br>
        Creation Date: {w.creation_date or 'Unknown'}<br>
        Expiration Date: {w.expiration_date or 'Unknown'}<br>
        Organization: {w.org or 'Unknown'}<br>
        Country: {w.country or 'Unknown'}<br>
        """
        return result
    except Exception as e:
        return f"WHOIS lookup failed for {domain}. Error: {str(e)}<br>"
