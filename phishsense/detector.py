"""
Phishing Detection Engine
Main detection logic combining ML and heuristic methods
"""

import pickle
import os
import numpy as np
from .feature_extractor import FeatureExtractor


class PhishDetector:
    """Main phishing detection class"""
    
    def __init__(self, model_path=None):
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.model_path = model_path or os.path.join(
            os.path.dirname(__file__), 'models', 'phishing_model.pkl'
        )
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained ML model"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
        except Exception as e:
            print(f"Warning: Could not load ML model: {e}")
            print("Using heuristic-only detection")
    
    def detect(self, url):
        """
        Detect if URL is phishing
        
        Args:
            url: URL to check
            
        Returns:
            dict: Detection results with confidence score and details
        """
        # Extract features
        features = self.feature_extractor.extract_features(url)
        
        # Heuristic analysis
        heuristic_score = self._heuristic_analysis(features, url)
        
        # ML prediction (if model available)
        ml_score = None
        ml_confidence = None
        if self.model:
            try:
                feature_vector = self._features_to_vector(features)
                prediction = self.model.predict([feature_vector])[0]
                probabilities = self.model.predict_proba([feature_vector])[0]
                ml_score = int(prediction)
                ml_confidence = float(max(probabilities))
            except Exception as e:
                print(f"ML prediction error: {e}")
        
        # Combine results
        final_score = self._combine_scores(heuristic_score, ml_score, ml_confidence)
        
        # Determine threat level
        threat_level = self._determine_threat_level(final_score)
        
        # Get reasons
        reasons = self._get_detection_reasons(features, url, final_score)
        
        return {
            'url': url,
            'is_phishing': final_score > 0.5,
            'confidence': final_score,
            'threat_level': threat_level,
            'heuristic_score': heuristic_score,
            'ml_score': ml_score,
            'ml_confidence': ml_confidence,
            'reasons': reasons,
            'features': features
        }
    
    def _heuristic_analysis(self, features, url):
        """Heuristic-based phishing detection"""
        score = 0.0
        max_score = 0.0
        
        # URL length (suspicious if very long)
        if features['url_length'] > 75:
            score += 0.1
        max_score += 0.1
        
        # Suspicious TLD
        if features['suspicious_tld']:
            score += 0.15
        max_score += 0.15
        
        # IP address in domain
        if features['has_ip']:
            score += 0.2
        max_score += 0.2
        
        # Shortened URL
        if features['is_shortened']:
            score += 0.1
        max_score += 0.1
        
        # Suspicious keywords
        if features['suspicious_keywords'] > 2:
            score += 0.15
        max_score += 0.15
        
        # Domain in subdomain (typosquatting)
        if features['domain_in_subdomain']:
            score += 0.15
        max_score += 0.15
        
        # No HTTPS
        if not features['has_https']:
            score += 0.1
        max_score += 0.1
        
        # Invalid SSL
        if features['has_https'] and not features['has_valid_ssl']:
            score += 0.15
        max_score += 0.15
        
        # New domain (age < 30 days)
        if features['domain_age'] > 0 and features['domain_age'] < 30:
            score += 0.1
        max_score += 0.1
        
        # High number of special characters
        special_chars = (features['num_percent'] + features['num_at_symbols'] + 
                        features['num_hashes'])
        if special_chars > 3:
            score += 0.1
        max_score += 0.1
        
        # Typosquatting patterns
        if features['is_typosquatting']:
            score += 0.1
        max_score += 0.1
        
        # Normalize score
        if max_score > 0:
            normalized_score = min(score / max_score, 1.0)
        else:
            normalized_score = 0.0
        
        return normalized_score
    
    def _features_to_vector(self, features):
        """Convert features dict to numpy array for ML model"""
        feature_order = [
            'url_length', 'hostname_length', 'path_length', 'query_length',
            'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_question_marks', 'num_equals', 'num_ampersands', 'num_percent',
            'num_at_symbols', 'has_https', 'has_http', 'domain_in_subdomain',
            'has_ip', 'is_shortened', 'suspicious_tld', 'suspicious_keywords',
            'has_port', 'num_params', 'has_redirect', 'domain_age',
            'has_valid_ssl', 'dns_record_count', 'is_typosquatting',
            'dots_to_length', 'hyphens_to_length'
        ]
        
        vector = []
        for feature in feature_order:
            vector.append(features.get(feature, 0))
        
        return np.array(vector)
    
    def _combine_scores(self, heuristic_score, ml_score, ml_confidence):
        """Combine heuristic and ML scores"""
        if ml_score is not None and ml_confidence is not None:
            # Weighted combination: More weight to ML if confidence is high
            if ml_confidence > 0.7:
                # High ML confidence: 70% ML, 30% heuristic
                combined = 0.3 * heuristic_score + 0.7 * (1.0 if ml_score == 1 else 0.0)
            elif ml_confidence > 0.5:
                # Medium ML confidence: 50% ML, 50% heuristic
                combined = 0.5 * heuristic_score + 0.5 * (1.0 if ml_score == 1 else 0.0)
            else:
                # Low ML confidence: 70% heuristic, 30% ML
                combined = 0.7 * heuristic_score + 0.3 * (1.0 if ml_score == 1 else 0.0)
        else:
            combined = heuristic_score
        
        return min(combined, 1.0)
    
    def _determine_threat_level(self, score):
        """Determine threat level from score"""
        if score >= 0.7:
            return "CRITICAL"
        elif score >= 0.5:
            return "HIGH"
        elif score >= 0.3:
            return "MEDIUM"
        elif score >= 0.15:
            return "LOW"
        else:
            return "SAFE"
    
    def _get_detection_reasons(self, features, url, score):
        """Get human-readable reasons for detection"""
        reasons = []
        
        if features['suspicious_tld']:
            reasons.append("Uses suspicious top-level domain")
        
        if features['has_ip']:
            reasons.append("Domain is an IP address")
        
        if features['is_shortened']:
            reasons.append("Uses URL shortening service")
        
        if features['domain_in_subdomain']:
            reasons.append("Legitimate domain appears in subdomain (possible typosquatting)")
        
        if features['suspicious_keywords'] > 2:
            reasons.append(f"Contains {features['suspicious_keywords']} suspicious keywords")
        
        if not features['has_https']:
            reasons.append("Does not use HTTPS")
        
        if features['has_https'] and not features['has_valid_ssl']:
            reasons.append("HTTPS certificate is invalid")
        
        if features['domain_age'] > 0 and features['domain_age'] < 30:
            reasons.append(f"Domain is very new ({features['domain_age']} days old)")
        
        if features['url_length'] > 75:
            reasons.append("URL is unusually long")
        
        if features['is_typosquatting']:
            reasons.append("Shows typosquatting patterns")
        
        if not reasons:
            reasons.append("No obvious phishing indicators detected")
        
        return reasons

