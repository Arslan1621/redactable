import re
from typing import List, Dict, Any

class SimplePIIDetector:
    """
    Simplified PII detector using only regex patterns.
    No external dependencies like spaCy or NumPy required.
    """
    
    def __init__(self):
        # Define regex patterns for different PII types
        self.patterns = {
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'confidence': 0.95
            },
            'phone': {
                'pattern': r'(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})',
                'confidence': 0.90
            },
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'confidence': 0.98
            },
            'credit_card': {
                'pattern': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                'confidence': 0.85
            },
            'zip_code': {
                'pattern': r'\b\d{5}(?:-\d{4})?\b',
                'confidence': 0.70
            },
            'date_of_birth': {
                'pattern': r'\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b',
                'confidence': 0.60
            },
            'name': {
                'pattern': r'\b[A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)?\b',
                'confidence': 0.50
            }
        }
    
    def detect_pii(self, text: str) -> Dict[str, Any]:
        """
        Detect PII in the given text using regex patterns.
        
        Args:
            text (str): Text to analyze
            
        Returns:
            Dict containing detections and summary
        """
        detections = []
        
        for pii_type, config in self.patterns.items():
            pattern = config['pattern']
            confidence = config['confidence']
            
            matches = re.finditer(pattern, text, re.IGNORECASE)
            
            for match in matches:
                detection = {
                    'text': match.group(),
                    'type': pii_type,
                    'confidence': confidence,
                    'start': match.start(),
                    'end': match.end()
                }
                detections.append(detection)
        
        # Remove overlapping detections (keep higher confidence)
        detections = self._remove_overlaps(detections)
        
        # Generate summary
        summary = self._generate_summary(detections)
        
        return {
            'detections': detections,
            'summary': summary
        }
    
    def _remove_overlaps(self, detections: List[Dict]) -> List[Dict]:
        """Remove overlapping detections, keeping the one with higher confidence."""
        if not detections:
            return detections
        
        # Sort by start position
        detections.sort(key=lambda x: x['start'])
        
        filtered = []
        for detection in detections:
            # Check if this detection overlaps with any in filtered list
            overlaps = False
            for existing in filtered:
                if (detection['start'] < existing['end'] and 
                    detection['end'] > existing['start']):
                    # There's an overlap
                    if detection['confidence'] > existing['confidence']:
                        # Remove the existing one and add this one
                        filtered.remove(existing)
                        filtered.append(detection)
                    overlaps = True
                    break
            
            if not overlaps:
                filtered.append(detection)
        
        return filtered
    
    def _generate_summary(self, detections: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics for detections."""
        total_detections = len(detections)
        high_confidence = len([d for d in detections if d['confidence'] >= 0.8])
        
        by_type = {}
        for detection in detections:
            pii_type = detection['type']
            by_type[pii_type] = by_type.get(pii_type, 0) + 1
        
        return {
            'total_detections': total_detections,
            'high_confidence': high_confidence,
            'by_type': by_type
        }
    
    def get_redaction_suggestions(self, detections: List[Dict]) -> Dict[str, Any]:
        """
        Generate intelligent redaction suggestions based on detected PII.
        
        Args:
            detections: List of PII detections
            
        Returns:
            Dict containing suggestions and risk assessment
        """
        if not detections:
            return {
                'risk_level': 'low',
                'priority_items': [],
                'suggestions': ['No sensitive information detected.']
            }
        
        # Assess risk level
        high_risk_types = {'ssn', 'credit_card'}
        medium_risk_types = {'email', 'phone', 'date_of_birth'}
        
        risk_level = 'low'
        high_confidence_count = len([d for d in detections if d['confidence'] >= 0.8])
        
        if any(d['type'] in high_risk_types for d in detections):
            risk_level = 'high'
        elif any(d['type'] in medium_risk_types for d in detections) or high_confidence_count >= 3:
            risk_level = 'medium'
        
        # Priority items (high confidence or high risk)
        priority_items = [
            d for d in detections 
            if d['confidence'] >= 0.8 or d['type'] in high_risk_types
        ]
        
        # Generate suggestions
        suggestions = []
        type_counts = {}
        for detection in detections:
            pii_type = detection['type']
            type_counts[pii_type] = type_counts.get(pii_type, 0) + 1
        
        if 'ssn' in type_counts:
            suggestions.append(f"Consider redacting all {type_counts['ssn']} Social Security Numbers for privacy compliance.")
        
        if 'email' in type_counts:
            suggestions.append(f"Review {type_counts['email']} email addresses - consider redacting personal emails.")
        
        if 'credit_card' in type_counts:
            suggestions.append(f"Redact all {type_counts['credit_card']} credit card numbers for PCI compliance.")
        
        if high_confidence_count >= 5:
            suggestions.append("High volume of sensitive data detected. Consider comprehensive redaction.")
        
        if not suggestions:
            suggestions.append("Review detected items and redact as needed based on your privacy requirements.")
        
        return {
            'risk_level': risk_level,
            'priority_items': priority_items,
            'suggestions': suggestions
        }

