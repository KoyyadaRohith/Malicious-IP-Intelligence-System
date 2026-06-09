def get_recommendations(classification):
    """
    Return action-oriented recommendations for security analysts
    based on the threat classification level.
    """
    if classification == "Safe":
        return [
            {"action": "Allow Communication", "priority": "Low", "description": "This IP exhibits no threat indicators. Normal network operations and ingress/egress transit are permitted."},
            {"action": "Standard Monitoring", "priority": "Low", "description": "Keep auditing connections in firewall logs as part of routine system maintenance."},
            {"action": "No Policy Changes", "priority": "Low", "description": "No immediate security changes or firewall blacklistings are required for this infrastructure."}
        ]
    elif classification == "Suspicious":
        return [
            {"action": "Monitor Port Connections", "priority": "Medium", "description": "Log and audit all active TCP/UDP ports communicating with this IP."},
            {"action": "Add to Active Watchlist", "priority": "Medium", "description": "Add this IP to the Watchlist database to monitor daily changes in threat scores."},
            {"action": "Review Internal Traffic", "priority": "Medium", "description": "Check if any local database or authentication servers are receiving connections from this host."}
        ]
    else: # Malicious
        return [
            {"action": "Block IP Address", "priority": "High", "description": "Apply immediate firewall block rules at the perimeter to drop all inbound and outbound traffic."},
            {"action": "Apply Null Route (Null0)", "priority": "High", "description": "Implement Null Route rules on primary routers to prevent packet routing to this target destination."},
            {"action": "Quarantine & Inspect Hosts", "priority": "High", "description": "Audit local server logs to see if internal nodes established handshake tunnels or active shell sessions with this IP."},
            {"action": "Escalate to Incident Response", "priority": "High", "description": "File an official Incident Response ticket (Severity 2/1) to investigate potential intrusion or compromise attempt."}
        ]
