import csv
import json
import os
import ipaddress
from datetime import datetime, timedelta, timezone

from config import Config
from services import abuseipdb as abuse
from services import virustotal as vt
from services import whois_lookup as whois
from services import risk_scoring as risk
from services import recommendations as recs
from services import threat_summary as summary

CACHE_FILE = Config.DB_FOLDER / 'threat_intel_cache.csv'

CACHE_FIELDS = [
    'ip_address',
    'timestamp_utc',
    'abuse_json',
    'vt_json',
    'whois_json',
    'risk_score',
    'classification',
    'recommendations_json',
    'last_updated_utc',
    'source_status',
    'cache_age_hours'
]


def _read_csv_rows():
    if not os.path.exists(CACHE_FILE):
        return []

    with open(CACHE_FILE, mode='r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        return list(reader)


def _write_csv_rows(rows):
    os.makedirs(Config.DB_FOLDER, exist_ok=True)
    with open(CACHE_FILE, mode='w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CACHE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _json_dumps_safe(v):
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return json.dumps({})


def _json_loads_safe(s, default=None):
    if default is None:
        default = {}
    try:
        if s is None or s == '':
            return default
        return json.loads(s)
    except Exception:
        return default


def _normalize_ip(ip: str) -> str:
    ip = (ip or '').strip()
    ipaddress.ip_address(ip)  # raises ValueError if invalid
    return str(ipaddress.ip_address(ip))


def _parse_time_utc(ts: str) -> datetime:
    # Handle both ISO strings with Z or without
    if not ts:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        if ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _cache_age_hours(now: datetime, then: datetime) -> float:
    delta = now - then
    return round(delta.total_seconds() / 3600.0, 3)


def _build_details(ip: str, abuse_data: dict, vt_data: dict, whois_data: dict, computed_meta: dict):
    risk_profile = risk.calculate_risk_score(abuse_data, vt_data, whois_data)
    threat_sum = summary.generate_threat_summary(
        ip,
        risk_profile['score'],
        risk_profile['classification'],
        abuse_data,
        vt_data,
        whois_data
    )
    recommendations = recs.get_recommendations(risk_profile['classification'])

    return {
        'ip': ip,
        'risk': risk_profile,
        'abuse': abuse_data,
        'vt': vt_data,
        'whois': whois_data,
        'summary': threat_sum,
        'recommendations': recommendations,
        'intel_meta': computed_meta
    }


def _refresh_from_sources(ip: str, cfg: dict):
    use_mock = cfg.get('mock_mode', True)

    if use_mock:
        abuse_data = abuse.get_mock_abuse_data(ip)
        vt_data = vt.get_mock_virustotal_data(ip)
        whois_data = whois.get_mock_whois_data(ip)
    else:
        ab_key = cfg.get('abuseipdb_key') or Config.ABUSEIPDB_API_KEY
        vt_key = cfg.get('virustotal_key') or Config.VIRUSTOTAL_API_KEY
        abuse_data = abuse.check_ip_abuse(ip, ab_key)
        vt_data = vt.check_ip_virustotal(ip, vt_key)
        whois_data = whois.get_whois_info(ip)

    computed_meta = {}
    return abuse_data, vt_data, whois_data, computed_meta


def _select_best_cached_row(ip: str):
    rows = _read_csv_rows()
    ip_rows = [r for r in rows if (r.get('ip_address') or '').strip() == ip]
    if not ip_rows:
        return None

    # Choose most recent by timestamp_utc
    ip_rows.sort(key=lambda r: _parse_time_utc(r.get('timestamp_utc', '')), reverse=True)
    return ip_rows[0]


def get_cached_intel(ip: str, cfg: dict, ttl_hours: int = 24, force_refresh: bool = False):
    """Cache-first threat intel fetch.

    Returns:
      details_dict (same structure expected by templates)
    """
    normalized_ip = _normalize_ip(ip)
    now = datetime.now(timezone.utc)

    cached_row = None if force_refresh else _select_best_cached_row(normalized_ip)

    if cached_row:
        cached_time = _parse_time_utc(cached_row.get('timestamp_utc'))
        age_h = _cache_age_hours(now, cached_time)
        if age_h < ttl_hours:
            abuse_data = _json_loads_safe(cached_row.get('abuse_json'), default={})
            vt_data = _json_loads_safe(cached_row.get('vt_json'), default={})
            whois_data = _json_loads_safe(cached_row.get('whois_json'), default={})
            risk_score = int(float(cached_row.get('risk_score', '0') or '0'))
            classification = cached_row.get('classification') or 'Safe'
            recommendations = _json_loads_safe(cached_row.get('recommendations_json'), default=[])

            # Re-generate score breakdown from cached inputs to guarantee stable math.
            # (Score itself is also cached, but recomputing ensures consistency with any hardened scoring logic.)
            risk_profile = risk.calculate_risk_score(abuse_data, vt_data, whois_data)

            threat_sum = summary.generate_threat_summary(
                normalized_ip,
                risk_profile['score'],
                risk_profile['classification'],
                abuse_data,
                vt_data,
                whois_data
            )

            intel_meta = {
                'last_updated_utc': cached_row.get('last_updated_utc', cached_row.get('timestamp_utc', '')),
                'source_status': cached_row.get('source_status', 'Cached Result'),
                'cache_age_hours': age_h,
                'cache_hit': True
            }

            # Prefer cached recommendations if present, else deterministic recompute.
            recommendations_final = recommendations if recommendations else recs.get_recommendations(risk_profile['classification'])

            return {
                'ip': normalized_ip,
                'risk': risk_profile,
                'abuse': abuse_data,
                'vt': vt_data,
                'whois': whois_data,
                'summary': threat_sum,
                'recommendations': recommendations_final,
                'intel_meta': intel_meta
            }

    # Cache miss or expired or forced refresh
    cfg_local = dict(cfg or {})
    # Ensure mock mode keys exist
    cfg_local.setdefault('mock_mode', True)

    abuse_data, vt_data, whois_data, _ = _refresh_from_sources(normalized_ip, cfg_local)

    risk_profile = risk.calculate_risk_score(abuse_data, vt_data, whois_data)
    threat_sum = summary.generate_threat_summary(
        normalized_ip,
        risk_profile['score'],
        risk_profile['classification'],
        abuse_data,
        vt_data,
        whois_data
    )
    recommendations = recs.get_recommendations(risk_profile['classification'])

    timestamp_utc = now.isoformat().replace('+00:00', 'Z')
    intel_meta = {
        'last_updated_utc': timestamp_utc,
        'source_status': 'Refreshed Result' if not cached_row else 'Refreshed Result (Expired)',
        'cache_age_hours': 0.0,
        'cache_hit': False
    }

    recommendations_json = _json_dumps_safe(recommendations)

    new_row = {
        'ip_address': normalized_ip,
        'timestamp_utc': timestamp_utc,
        'abuse_json': _json_dumps_safe(abuse_data),
        'vt_json': _json_dumps_safe(vt_data),
        'whois_json': _json_dumps_safe(whois_data),
        'risk_score': str(risk_profile['score']),
        'classification': risk_profile['classification'],
        'recommendations_json': recommendations_json,
        'last_updated_utc': timestamp_utc,
        'source_status': intel_meta['source_status'],
        'cache_age_hours': str(intel_meta['cache_age_hours'])
    }

    rows = _read_csv_rows()
    # Remove previous cached rows for this IP (keep one latest)
    rows = [r for r in rows if (r.get('ip_address') or '').strip() != normalized_ip]
    rows.append(new_row)
    _write_csv_rows(rows)

    return {
        'ip': normalized_ip,
        'risk': risk_profile,
        'abuse': abuse_data,
        'vt': vt_data,
        'whois': whois_data,
        'summary': threat_sum,
        'recommendations': recommendations,
        'intel_meta': intel_meta
    }

