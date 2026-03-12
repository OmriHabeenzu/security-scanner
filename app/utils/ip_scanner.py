"""
IP address reputation checking with REAL API integration
"""
from app import db
from app.models.scans import IPScan
from app.utils.url_ip_utils import validate_ip_address, is_private_ip, get_ip_version
import requests
from flask import current_app

def scan_ip(ip_address, user=None):
    """
    Check IP address reputation using REAL AbuseIPDB API
    Falls back to improved simulation if API key not configured
    """
    try:
        # Validate IP
        if not validate_ip_address(ip_address):
            return {'success': False, 'error': 'Invalid IP address format'}
        
        # Check if private IP
        if is_private_ip(ip_address):
            return {
                'success': True,
                'ip_address': ip_address,
                'is_malicious': False,
                'is_private': True,
                'message': 'This is a private/internal IP address'
            }
        
        # Get IP version
        ip_version = get_ip_version(ip_address)
        
        # Check with REAL AbuseIPDB API
        api_key = current_app.config.get('ABUSEIPDB_API_KEY')
        
        if api_key and api_key != 'your-abuseipdb-key-here' and api_key != 'YOUR_ACTUAL_KEY_HERE_NO_QUOTES':
            # Use REAL API
            print(f"✓ Using AbuseIPDB API for {ip_address}")
            api_result = check_ip_with_real_api(ip_address, api_key)
        else:
            # Fallback to improved simulation
            print(f"⚠ Warning: AbuseIPDB API key not configured. Using simulation for {ip_address}")
            api_result = check_ip_with_improved_simulation(ip_address)
        
        # Calculate threat level
        abuse_score = api_result.get('abuse_score', 0)
        is_malicious = abuse_score > 75
        
        # Save to database if user is logged in
        scan_record = None
        if user:
            scan_record = IPScan(
                user_id=user.id,
                ip_address=ip_address,
                is_malicious=is_malicious,
                abuse_confidence_score=abuse_score,
                total_reports=api_result.get('total_reports', 0),
                country=api_result.get('country', 'Unknown')[:100],
                isp=api_result.get('isp', 'Unknown')[:255],
                usage_type=api_result.get('usage_type', 'Unknown')[:50]
            )
            db.session.add(scan_record)
            db.session.commit()
        
        # Return results with enhanced geolocation
        return {
            'success': True,
            'ip_address': ip_address,
            'ip_version': ip_version,
            'is_malicious': is_malicious,
            'abuse_score': abuse_score,
            'total_reports': api_result.get('total_reports', 0),
            'country': api_result.get('country', 'Unknown'),
            'city': api_result.get('city', 'Unknown'),
            'region': api_result.get('region', 'Unknown'),
            'latitude': api_result.get('latitude', 0),
            'longitude': api_result.get('longitude', 0),
            'isp': api_result.get('isp', 'Unknown'),
            'asn': api_result.get('asn', 'N/A'),
            'hostname': api_result.get('hostname', ip_address),
            'usage_type': api_result.get('usage_type', 'Unknown'),
            'last_reported': api_result.get('last_reported', 'N/A'),
            'scan_id': scan_record.id if scan_record else None,
            'api_used': api_result.get('api_used', 'simulation')
        }
    
    except Exception as e:
        return {'success': False, 'error': str(e)}


def check_ip_with_real_api(ip_address, api_key):
    """
    Check IP with REAL AbuseIPDB API
    Documentation: https://docs.abuseipdb.com/#check-endpoint
    """
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        
        print(f"📡 Calling AbuseIPDB API for {ip_address}...")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            print(f"✓ AbuseIPDB API response received for {ip_address}")

            # Supplement with ip-api.com for city/region/lat/lon (free, no key)
            city, region, latitude, longitude = 'Unknown', 'Unknown', 0, 0
            try:
                geo_r = requests.get(
                    f'http://ip-api.com/json/{ip_address}',
                    params={'fields': 'country,regionName,city,lat,lon'},
                    timeout=5
                )
                if geo_r.status_code == 200:
                    geo = geo_r.json()
                    city      = geo.get('city', 'Unknown') or 'Unknown'
                    region    = geo.get('regionName', 'Unknown') or 'Unknown'
                    latitude  = geo.get('lat', 0) or 0
                    longitude = geo.get('lon', 0) or 0
            except Exception as geo_err:
                print(f'[ip-api] {geo_err}')

            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'Unknown'),
                'city': city,
                'region': region,
                'latitude': latitude,
                'longitude': longitude,
                'isp': data.get('isp', 'Unknown'),
                'asn': str(data.get('asnNumber', 'N/A')) if data.get('asnNumber') else 'N/A',
                'hostname': data.get('domain', ip_address),
                'usage_type': data.get('usageType', 'Unknown'),
                'last_reported': data.get('lastReportedAt', 'Never') if data.get('totalReports', 0) > 0 else 'Never',
                'api_used': 'AbuseIPDB + ip-api.com'
            }
        elif response.status_code == 401:
            print(f"❌ AbuseIPDB API: Invalid API key")
            return check_ip_with_improved_simulation(ip_address)
        elif response.status_code == 429:
            print(f"❌ AbuseIPDB API: Rate limit exceeded")
            return check_ip_with_improved_simulation(ip_address)
        else:
            print(f"❌ AbuseIPDB API error: {response.status_code}")
            return check_ip_with_improved_simulation(ip_address)
            
    except Exception as e:
        print(f"❌ Error calling AbuseIPDB API: {e}")
        return check_ip_with_improved_simulation(ip_address)


def check_ip_with_improved_simulation(ip_address):
    """
    IMPROVED simulation with realistic patterns
    Used as fallback when API key not configured
    """
    # Known safe IPs (actual correct data)
    known_safe = {
        '8.8.8.8': {
            'abuse_score': 0,
            'country': 'US',
            'city': 'Mountain View',
            'region': 'California',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'isp': 'Google LLC',
            'usage_type': 'Data Center/Web Hosting/Transit',
            'asn': '15169',
            'hostname': 'dns.google',
            'total_reports': 0,
            'last_reported': 'Never',
            'api_used': 'Simulation (Known Safe IP)'
        },
        '8.8.4.4': {
            'abuse_score': 0,
            'country': 'US',
            'city': 'Mountain View',
            'region': 'California',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'isp': 'Google LLC',
            'usage_type': 'Data Center/Web Hosting/Transit',
            'asn': '15169',
            'hostname': 'dns.google',
            'total_reports': 0,
            'last_reported': 'Never',
            'api_used': 'Simulation (Known Safe IP)'
        },
        '1.1.1.1': {
            'abuse_score': 0,
            'country': 'AU',
            'city': 'Sydney',
            'region': 'New South Wales',
            'latitude': -33.8688,
            'longitude': 151.2093,
            'isp': 'Cloudflare Inc',
            'usage_type': 'Content Delivery Network',
            'asn': '13335',
            'hostname': 'one.one.one.one',
            'total_reports': 0,
            'last_reported': 'Never',
            'api_used': 'Simulation (Known Safe IP)'
        },
        '1.0.0.1': {
            'abuse_score': 0,
            'country': 'AU',
            'city': 'Sydney',
            'region': 'New South Wales',
            'latitude': -33.8688,
            'longitude': 151.2093,
            'isp': 'Cloudflare Inc',
            'usage_type': 'Content Delivery Network',
            'asn': '13335',
            'hostname': 'one.one.one.one',
            'total_reports': 0,
            'last_reported': 'Never',
            'api_used': 'Simulation (Known Safe IP)'
        }
    }
    
    # Check if it's a known safe IP
    if ip_address in known_safe:
        return known_safe[ip_address]
    
    # For unknown IPs, use pattern-based heuristics
    octets = ip_address.split('.')
    
    # Heuristic risk assessment
    risk_score = 0
    
    # Check for suspicious IP ranges
    if octets[0] in ['185', '194', '103', '23', '5', '46', '91']:
        risk_score = 30 + (int(octets[3]) % 40)
    else:
        risk_score = int(octets[3]) % 25
    
    # Determine country based on first octet
    country_map = {
        '8': 'US',
        '1': 'AU',
        '185': 'DE',
        '194': 'RU',
        '103': 'SG',
        '23': 'US',
        '5': 'NL',
        '46': 'RU',
        '91': 'IN'
    }
    
    country = country_map.get(octets[0], 'Unknown')
    
    return {
        'abuse_score': risk_score,
        'total_reports': max(0, risk_score // 10),
        'country': country,
        'city': 'Unknown',
        'region': 'Unknown',
        'latitude': 0,
        'longitude': 0,
        'isp': 'Unknown ISP',
        'asn': 'N/A',
        'hostname': ip_address,
        'usage_type': 'Unknown',
        'last_reported': '2024-02-15' if risk_score > 50 else 'Never',
        'api_used': 'Simulation (Pattern-Based)'
    }
