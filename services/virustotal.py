import requests
import hashlib
import random
from config import Config

def check_ip_virustotal(ip, api_key=None):
    """
    Query VirusTotal v3 IP Address API.
    If no API key is present or error occurs, falls back to deterministic mock data.
    """
    key = api_key or Config.VIRUSTOTAL_API_KEY
    
    if key and key.strip():
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {
            'x-apikey': key
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                attributes = response.json().get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                votes = attributes.get('reputation', 0)
                
                # Extract malicious detections and security vendors
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                tags = attributes.get('tags', [])
                asn = attributes.get('asn', 0)
                network = attributes.get('network', '')
                
                return {
                    'ip': ip,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'harmless_count': harmless,
                    'undetected_count': undetected,
                    'total_engines': total or 90,
                    'reputation_score': votes,
                    'tags': tags[:5],
                    'network': network,
                    'asn': asn,
                    'is_mock': False
                }
        except Exception:
            pass
            
    # Mock fallback
    return get_mock_virustotal_data(ip)

def get_mock_virustotal_data(ip):
    """Generates realistic mock VT data seeded by the IP hash for consistency."""
    ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    random.seed(ip_hash)
    
    # Calculate mock risk category deterministically
    risk_factor = ip_hash % 100
    
    total_engines = 89
    if risk_factor < 50: # Safe
        malicious = 0
        suspicious = 0
        harmless = random.randint(70, 80)
        undetected = total_engines - harmless
        reputation = random.randint(0, 10)
        tags = []
    elif risk_factor < 80: # Suspicious
        malicious = random.randint(1, 8)
        suspicious = random.randint(1, 4)
        harmless = random.randint(50, 65)
        undetected = total_engines - harmless - malicious - suspicious
        reputation = -random.randint(5, 25)
        tags = random.sample(["vpn", "crawler", "ssh-scan", "hosting"], random.randint(1, 2))
    else: # Malicious
        malicious = random.randint(15, 62)
        suspicious = random.randint(2, 8)
        harmless = random.randint(10, 25)
        undetected = total_engines - harmless - malicious - suspicious
        reputation = -random.randint(40, 180)
        tags = random.sample(["botnet", "malware-distribution", "phishing", "brute-force", "ddos", "c2"], random.randint(2, 4))
        
    # Map network and ASN based on risk level
    asns = [13335, 16509, 14061, 24940, 32244, 4134, 4837]
    asn = random.choice(asns)
    network = f"{ip.split('.')[0]}.{ip.split('.')[1]}.0.0/16"

    return {
        'ip': ip,
        'malicious_count': malicious,
        'suspicious_count': suspicious,
        'harmless_count': harmless,
        'undetected_count': undetected,
        'total_engines': total_engines,
        'reputation_score': reputation,
        'tags': tags,
        'network': network,
        'asn': asn,
        'is_mock': True
    }
