from flask import Blueprint, request, jsonify
from src.simple_pii_detector import SimplePIIDetector

redaction_bp = Blueprint('redaction', __name__)

# Initialize PII detector
pii_detector = SimplePIIDetector()

@redaction_bp.route('/analyze', methods=['POST'])
def analyze_text():
    """Analyze text for PII without file upload"""
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({'error': 'Text is required'}), 400
        
        text = data['text']
        if not text.strip():
            return jsonify({'error': 'Text cannot be empty'}), 400
        
        # Perform PII analysis
        pii_analysis = pii_detector.generate_redaction_suggestions(text)
        
        return jsonify({
            'success': True,
            'analysis': pii_analysis
        }), 200
        
    except Exception as e:
        print(f"Text analysis error: {e}")
        return jsonify({'error': 'Internal server error during text analysis'}), 500

@redaction_bp.route('/preview', methods=['POST'])
def preview_redaction():
    """Preview text with suggested redactions applied"""
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({'error': 'Text is required'}), 400
        
        text = data['text']
        redaction_options = data.get('options', {})
        
        if not text.strip():
            return jsonify({'error': 'Text cannot be empty'}), 400
        
        # Get PII detections
        pii_analysis = pii_detector.generate_redaction_suggestions(text)
        detections = pii_analysis['detections']
        
        # Apply redactions based on options
        redacted_text = apply_redactions(text, detections, redaction_options)
        
        return jsonify({
            'success': True,
            'original_text': text,
            'redacted_text': redacted_text,
            'redactions_applied': len([d for d in detections if should_redact(d, redaction_options)]),
            'total_detections': len(detections)
        }), 200
        
    except Exception as e:
        print(f"Redaction preview error: {e}")
        return jsonify({'error': 'Internal server error during redaction preview'}), 500

def should_redact(detection, options):
    """Determine if a detection should be redacted based on options"""
    # Default redaction settings
    default_settings = {
        'redact_names': True,
        'redact_emails': True,
        'redact_phones': True,
        'redact_ssns': True,
        'redact_credit_cards': True,
        'redact_organizations': False,
        'redact_zip_codes': False,
        'redact_dates': False,
        'min_confidence': 0.5
    }
    
    # Merge with user options
    settings = {**default_settings, **options}
    
    # Check confidence threshold
    if detection['confidence'] < settings['min_confidence']:
        return False
    
    # Check type-specific settings
    detection_type = detection['type']
    type_mapping = {
        'name': 'redact_names',
        'email': 'redact_emails',
        'phone': 'redact_phones',
        'ssn': 'redact_ssns',
        'credit_card': 'redact_credit_cards',
        'organization': 'redact_organizations',
        'zip_code': 'redact_zip_codes',
        'date_of_birth': 'redact_dates'
    }
    
    setting_key = type_mapping.get(detection_type)
    if setting_key:
        return settings.get(setting_key, False)
    
    return False

def apply_redactions(text, detections, options):
    """Apply redactions to text based on detections and options"""
    if not detections:
        return text
    
    # Filter detections based on options
    to_redact = [d for d in detections if should_redact(d, options)]
    
    if not to_redact:
        return text
    
    # Sort by start position in reverse order to maintain indices
    to_redact.sort(key=lambda x: x['start'], reverse=True)
    
    redacted_text = text
    redaction_char = options.get('redaction_char', '█')
    
    for detection in to_redact:
        start = detection['start']
        end = detection['end']
        original_text = detection['text']
        
        # Create redaction replacement
        if options.get('preserve_length', True):
            # Replace with same length of redaction characters
            replacement = redaction_char * len(original_text)
        else:
            # Replace with type indicator
            type_labels = {
                'name': '[NAME]',
                'email': '[EMAIL]',
                'phone': '[PHONE]',
                'ssn': '[SSN]',
                'credit_card': '[CREDIT_CARD]',
                'organization': '[ORG]',
                'zip_code': '[ZIP]',
                'date_of_birth': '[DATE]'
            }
            replacement = type_labels.get(detection['type'], '[REDACTED]')
        
        # Apply redaction
        redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
    
    return redacted_text

@redaction_bp.route('/suggestions', methods=['POST'])
def get_redaction_suggestions():
    """Get intelligent redaction suggestions based on document type and content"""
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({'error': 'Text is required'}), 400
        
        text = data['text']
        document_type = data.get('document_type', 'general')
        
        if not text.strip():
            return jsonify({'error': 'Text cannot be empty'}), 400
        
        # Get PII analysis
        pii_analysis = pii_detector.generate_redaction_suggestions(text)
        
        # Generate context-aware suggestions
        smart_suggestions = generate_smart_suggestions(pii_analysis, document_type, text)
        
        return jsonify({
            'success': True,
            'pii_analysis': pii_analysis,
            'smart_suggestions': smart_suggestions
        }), 200
        
    except Exception as e:
        print(f"Suggestions error: {e}")
        return jsonify({'error': 'Internal server error during suggestion generation'}), 500

def generate_smart_suggestions(pii_analysis, document_type, text):
    """Generate intelligent redaction suggestions based on context"""
    detections = pii_analysis['detections']
    suggestions = []
    
    if not detections:
        return {
            'recommended_settings': {
                'redact_names': False,
                'redact_emails': False,
                'redact_phones': False,
                'redact_ssns': False,
                'min_confidence': 0.5
            },
            'reasoning': ['No sensitive information detected in this document.'],
            'risk_level': 'low'
        }
    
    # Analyze risk level
    high_risk_types = ['ssn', 'credit_card']
    medium_risk_types = ['email', 'phone', 'name']
    
    high_risk_count = len([d for d in detections if d['type'] in high_risk_types])
    medium_risk_count = len([d for d in detections if d['type'] in medium_risk_types])
    
    if high_risk_count > 0:
        risk_level = 'high'
    elif medium_risk_count > 2:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    # Generate recommendations based on document type and risk
    recommended_settings = {
        'redact_names': True,
        'redact_emails': True,
        'redact_phones': True,
        'redact_ssns': True,
        'redact_credit_cards': True,
        'redact_organizations': False,
        'redact_zip_codes': False,
        'redact_dates': False,
        'min_confidence': 0.7 if risk_level == 'high' else 0.5
    }
    
    reasoning = []
    
    if document_type == 'medical':
        recommended_settings['redact_dates'] = True
        reasoning.append("Medical documents typically require redaction of dates and personal identifiers.")
    elif document_type == 'financial':
        recommended_settings['redact_zip_codes'] = True
        reasoning.append("Financial documents should have all personal and location data redacted.")
    elif document_type == 'legal':
        recommended_settings['redact_organizations'] = True
        reasoning.append("Legal documents may require redaction of organization names for confidentiality.")
    
    if high_risk_count > 0:
        reasoning.append(f"High-risk information detected ({high_risk_count} items). Recommend strict redaction settings.")
    
    if len(detections) > 5:
        reasoning.append("Multiple sensitive items detected. Consider comprehensive redaction.")
    
    return {
        'recommended_settings': recommended_settings,
        'reasoning': reasoning,
        'risk_level': risk_level,
        'priority_items': [d for d in detections if d['confidence'] >= 0.8]
    }

