def calculate_risk_score(abuse_data, vt_data, whois_data):
    """Calculate an aggregate threat intelligence risk score (0-100).

    Design goals:
    - Deterministic: identical intelligence inputs => identical score.
    - Robust: missing fields never cause score drift due to defaulting differences.
    - Safe: any unexpected data types are sanitized into numeric defaults.
    """

    abuse_data = abuse_data or {}
    vt_data = vt_data or {}
    whois_data = whois_data or {}

    def _to_int(v, default=0):
        try:
            if v is None or v == '':
                return default
            return int(float(v))
        except Exception:
            return default

    def _to_float(v, default=0.0):
        try:
            if v is None or v == '':
                return default
            return float(v)
        except Exception:
            return default

    # 1) AbuseIPDB confidence score weight: 50%
    abuse_score = _to_float(abuse_data.get('abuse_score', 0), default=0.0)
    # clamp abuse_score to [0,100]
    abuse_score = max(0.0, min(100.0, abuse_score))
    weighted_abuse = abuse_score * 0.50

    # 2) VirusTotal malicious detections weight: 35%
    vt_malicious = _to_int(vt_data.get('malicious_count', 0), default=0)
    vt_total = _to_int(vt_data.get('total_engines', 89), default=89)
    vt_total = max(0, vt_total)

    if vt_total > 0:
        vt_ratio_score = (vt_malicious / vt_total) * 100.0
    else:
        vt_ratio_score = 0.0

    # Cap VT contribution to 35
    weighted_vt = min(vt_ratio_score * 0.35, 35.0)

    # 3) WHOIS / hosting profile weight: 15% (derived from AbuseIPDB usage_type + VT tags)
    weighted_whois = 0
    usage_type = str(abuse_data.get('usage_type', '') or '').lower()

    if 'data center' in usage_type or 'hosting' in usage_type:
        weighted_whois += 8

    vt_tags_raw = vt_data.get('tags', []) or []
    # Ensure vt_tags is a list of strings
    vt_tags = []
    if isinstance(vt_tags_raw, list):
        vt_tags = [str(t).lower() for t in vt_tags_raw]

    if any(tag in vt_tags for tag in ['vpn', 'proxy', 'tor', 'anonymous']):
        weighted_whois += 7

    # Aggregate total score (deterministic rounding)
    total_score = int(round(weighted_abuse + weighted_vt + weighted_whois))

    final_score = max(0, min(100, total_score))

    # Classification thresholds (deterministic)
    if final_score <= 20:
        classification = "Safe"
    elif final_score <= 60:
        classification = "Suspicious"
    else:
        classification = "Malicious"

    return {
        'score': final_score,
        'classification': classification,
        'breakdown': {
            'abuse_contribution': round(weighted_abuse, 1),
            'vt_contribution': round(weighted_vt, 1),
            'profile_contribution': round(float(weighted_whois), 1)
        }
    }

