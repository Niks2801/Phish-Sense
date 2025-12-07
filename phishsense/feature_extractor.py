"""
Feature Extraction Module
Extracts various features from URLs to detect phishing attempts
"""

import re
import urllib.parse
import socket
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import ssl

# Optional imports - handle gracefully if not installed
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: python-whois not installed. Domain age checking will be disabled.")
    print("Install with: pip install python-whois")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests not installed. Some features may be limited.")

try:
    import tldextract
    TL_EXTRACT_AVAILABLE = True
except ImportError:
    TL_EXTRACT_AVAILABLE = False
    print("Warning: tldextract not installed. Some domain features may be limited.")


class FeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'secure', 'verify', 'account', 'update', 'confirm', 'login',
            'signin', 'banking', 'ebayisapi', 'paypal', 'webscr', 'secure',
            'account', 'update', 'confirm', 'suspend', 'restrict', 'limited',
            'unusual', 'activity', 'verify', 'validate', 'urgent', 'immediate'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        
        self.shortening_services = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
            'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 'v.gd', 'vzturl.com'
        ]
    
    def extract_features(self, url):
        """
        Extract all features from a URL
        
        Args:
            url: The URL to analyze
            
        Returns:
            dict: Dictionary of extracted features
        """
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['hostname_length'] = len(urlparse(url).netloc)
        features['path_length'] = len(urlparse(url).path)
        features['query_length'] = len(urlparse(url).query)
        
        # Count features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ampersands'] = url.count('&')
        features['num_percent'] = url.count('%')
        features['num_at_symbols'] = url.count('@')
        features['num_exclamation'] = url.count('!')
        features['num_spaces'] = url.count(' ')
        features['num_tildes'] = url.count('~')
        features['num_commas'] = url.count(',')
        features['num_plus'] = url.count('+')
        features['num_asterisks'] = url.count('*')
        features['num_hashes'] = url.count('#')
        features['num_dollar'] = url.count('$')
        features['num_colons'] = url.count(':')
        
        # Protocol features
        features['has_https'] = 1 if urlparse(url).scheme == 'https' else 0
        features['has_http'] = 1 if urlparse(url).scheme == 'http' else 0
        features['has_ftp'] = 1 if urlparse(url).scheme == 'ftp' else 0
        
        # Domain features
        parsed = urlparse(url)
        domain = parsed.netloc
        features['domain_in_subdomain'] = self._check_domain_in_subdomain(domain)
        features['has_ip'] = 1 if self._has_ip_address(domain) else 0
        features['is_shortened'] = 1 if self._is_shortened_url(domain) else 0
        features['suspicious_tld'] = 1 if self._has_suspicious_tld(domain) else 0
        
        # Path features
        path = parsed.path.lower()
        features['suspicious_keywords'] = self._count_suspicious_keywords(url.lower())
        features['has_port'] = 1 if ':' in domain and not domain.startswith('[') else 0
        
        # Query features
        query = parsed.query
        features['num_params'] = len(parse_qs(query))
        features['has_redirect'] = 1 if 'redirect' in query.lower() or 'url=' in query.lower() else 0
        
        # Advanced features
        features['domain_age'] = self._get_domain_age(domain)
        features['has_valid_ssl'] = self._check_ssl_certificate(domain)
        features['dns_record_count'] = self._get_dns_record_count(domain)
        features['is_typosquatting'] = self._check_typosquatting(domain)
        
        # Ratio features
        if features['url_length'] > 0:
            features['dots_to_length'] = features['num_dots'] / features['url_length']
            features['hyphens_to_length'] = features['num_hyphens'] / features['url_length']
        else:
            features['dots_to_length'] = 0
            features['hyphens_to_length'] = 0
        
        return features
    
    def _check_domain_in_subdomain(self, domain):
        """Check if legitimate domain appears in subdomain"""
        common_domains = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 
                         'paypal', 'ebay', 'bank', 'wellsfargo', 'chase']
        domain_lower = domain.lower()
        for common in common_domains:
            if common in domain_lower and domain_lower != common:
                return 1
        return 0
    
    def _has_ip_address(self, domain):
        """Check if domain is an IP address"""
        try:
            socket.inet_aton(domain.replace('[', '').replace(']', ''))
            return True
        except:
            return False
    
    def _is_shortened_url(self, domain):
        """Check if URL uses shortening service"""
        for service in self.shortening_services:
            if service in domain.lower():
                return True
        return False
    
    def _has_suspicious_tld(self, domain):
        """Check for suspicious TLDs"""
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True
        return False
    
    def _count_suspicious_keywords(self, url):
        """Count suspicious keywords in URL"""
        count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url:
                count += 1
        return count
    
    def _get_domain_age(self, domain):
        """Get domain age in days (0 if can't determine)"""
        if not WHOIS_AVAILABLE:
            return 0
        
        try:
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                if creation_date:
                    age = (datetime.now() - creation_date).days
                    return age if age > 0 else 0
        except:
            pass
        return 0
    
    def _check_ssl_certificate(self, domain):
        """Check if domain has valid SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return 1
        except:
            return 0
    
    def _get_dns_record_count(self, domain):
        """Get count of DNS records (simplified)"""
        try:
            socket.gethostbyname(domain)
            return 1
        except:
            return 0
    
    def _check_typosquatting(self, domain):
        """Check for typosquatting patterns"""
        # Simple check for character repetition or suspicious patterns
        if re.search(r'(.)\1{3,}', domain):
            return 1
        if len(re.findall(r'[0-9]', domain)) > 3:
            return 1
        return 0

