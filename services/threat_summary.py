def generate_threat_summary(ip, risk_score, classification, abuse_data, vt_data, whois_data):
    """
    Generate an analyst-style threat intelligence summary detailing
    key findings and malicious behavior patterns.
    """
    country = whois_data.get('country', 'Unknown')
    isp = whois_data.get('isp', 'Unknown')
    asn = whois_data.get('asn', 'Unknown')
    abuse_score = abuse_data.get('abuse_score', 0)
    vt_malicious = vt_data.get('malicious_count', 0)
    vt_total = vt_data.get('total_engines', 89)
    total_reports = abuse_data.get('total_reports', 0)
    usage_type = abuse_data.get('usage_type', 'unknown')
    
    if classification == "Safe":
        return (
            f"The investigated IP address ({ip}) is classified as SAFE with an aggregate risk score of {risk_score}/100. "
            f"Reputation profiling indicates this IP belongs to a reputable infrastructure provider, '{isp}' ({asn}) "
            f"located in {country}. Neither AbuseIPDB ({total_reports} reports) nor VirusTotal security engines "
            f"({vt_malicious}/{vt_total} detections) indicate any active compromise or threat vectors. "
            f"Communication with this IP is considered low risk."
        )
    elif classification == "Suspicious":
        tags_str = f" Tags identified: {', '.join(vt_data.get('tags', []))}." if vt_data.get('tags') else ""
        return (
            f"The investigated IP address ({ip}) is classified as SUSPICIOUS with an aggregate risk score of {risk_score}/100. "
            f"It is registered under '{isp}' ({asn}) in {country} and operates as a '{usage_type}'. "
            f"AbuseIPDB reputation reports an abuse confidence score of {abuse_score}% based on {total_reports} reports over the last 90 days. "
            f"VirusTotal detected suspicious activity across {vt_malicious} threat intelligence feeds.{tags_str} "
            f"The IP is likely used as a public VPN proxy, crawling agent, or shared hosting node, warranting proactive network monitoring."
        )
    else: # Malicious
        tags_list = vt_data.get('tags', [])
        activity_type = f" (exhibiting {', '.join(tags_list)})" if tags_list else ""
        return (
            f"CRITICAL THREAT DETECTED: The IP address {ip} is classified as MALICIOUS with a severe risk score of {risk_score}/100. "
            f"Infrastructure analysis associates this IP with '{isp}' ({asn}) operating in {country}. "
            f"AbuseIPDB report database correlates an active abuse score of {abuse_score}% with {total_reports} security violations. "
            f"Furthermore, VirusTotal reports severe warnings with {vt_malicious}/{vt_total} AV engines flags{activity_type}. "
            f"This IP is confirmed to be part of a malicious network node involved in unauthorized access attempts, botnet operations, "
            f"or malware propagation. Immediate isolation is advised."
        )
