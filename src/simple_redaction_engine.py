import json
import os
from datetime import datetime
from typing import List, Dict, Any

class SimpleRedactionEngine:
    """
    Simplified redaction engine using only standard library.
    No external dependencies required.
    """
    
    def __init__(self):
        self.redaction_styles = {
            'black_bars': '█',
            'asterisks': '*',
            'labels': True  # Use type-specific labels
        }
        
        self.type_labels = {
            'name': '[NAME_REDACTED]',
            'email': '[EMAIL_REDACTED]',
            'phone': '[PHONE_REDACTED]',
            'ssn': '[SSN_REDACTED]',
            'credit_card': '[CARD_REDACTED]',
            'zip_code': '[ZIP_REDACTED]',
            'date_of_birth': '[DOB_REDACTED]'
        }
    
    def apply_redactions(self, text: str, detections: List[Dict], 
                        redaction_options: Dict = None) -> Dict[str, Any]:
        """
        Apply redactions to text based on selected detections.
        
        Args:
            text (str): Original text
            detections (List[Dict]): List of PII detections to redact
            redaction_options (Dict): Redaction configuration options
            
        Returns:
            Dict containing redacted text and metadata
        """
        if not redaction_options:
            redaction_options = {
                'style': 'black_bars',
                'preserve_length': True,
                'confidence_threshold': 0.0
            }
        
        # Filter detections based on confidence threshold
        filtered_detections = [
            d for d in detections 
            if d.get('confidence', 0) >= redaction_options.get('confidence_threshold', 0)
        ]
        
        # Sort detections by start position (reverse order for proper replacement)
        filtered_detections.sort(key=lambda x: x.get('start', 0), reverse=True)
        
        redacted_text = text
        redacted_items = []
        
        for detection in filtered_detections:
            start = detection.get('start', 0)
            end = detection.get('end', len(detection['text']))
            original_text = detection['text']
            pii_type = detection['type']
            
            # Generate replacement text
            replacement = self._generate_replacement(
                original_text, pii_type, redaction_options
            )
            
            # Apply redaction
            redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
            
            redacted_items.append({
                'original_text': original_text,
                'type': pii_type,
                'confidence': detection.get('confidence', 0),
                'position': {'start': start, 'end': end},
                'replacement': replacement
            })
        
        # Generate audit trail
        audit_trail = self._generate_audit_trail(
            original_text=text,
            redacted_text=redacted_text,
            redacted_items=redacted_items,
            redaction_options=redaction_options
        )
        
        return {
            'redacted_text': redacted_text,
            'redacted_items': redacted_items,
            'audit_trail': audit_trail,
            'summary': {
                'total_redactions': len(redacted_items),
                'by_type': self._count_by_type(redacted_items)
            }
        }
    
    def _generate_replacement(self, original_text: str, pii_type: str, 
                            options: Dict) -> str:
        """Generate replacement text for redaction."""
        style = options.get('style', 'black_bars')
        preserve_length = options.get('preserve_length', True)
        
        if style == 'labels':
            return self.type_labels.get(pii_type, '[REDACTED]')
        
        if preserve_length:
            char = self.redaction_styles.get(style, '█')
            return char * len(original_text)
        else:
            if style == 'black_bars':
                return '████████'
            elif style == 'asterisks':
                return '********'
            else:
                return '[REDACTED]'
    
    def _generate_audit_trail(self, original_text: str, redacted_text: str,
                            redacted_items: List[Dict], redaction_options: Dict) -> Dict:
        """Generate audit trail for the redaction process."""
        return {
            'timestamp': datetime.now().isoformat(),
            'redaction_options': redaction_options,
            'original_length': len(original_text),
            'redacted_length': len(redacted_text),
            'redacted_items': redacted_items,
            'summary': {
                'total_redactions': len(redacted_items),
                'by_type': self._count_by_type(redacted_items),
                'by_confidence': self._count_by_confidence(redacted_items)
            }
        }
    
    def _count_by_type(self, redacted_items: List[Dict]) -> Dict[str, int]:
        """Count redacted items by type."""
        counts = {}
        for item in redacted_items:
            pii_type = item['type']
            counts[pii_type] = counts.get(pii_type, 0) + 1
        return counts
    
    def _count_by_confidence(self, redacted_items: List[Dict]) -> Dict[str, int]:
        """Count redacted items by confidence level."""
        counts = {'high': 0, 'medium': 0, 'low': 0}
        for item in redacted_items:
            confidence = item.get('confidence', 0)
            if confidence >= 0.8:
                counts['high'] += 1
            elif confidence >= 0.5:
                counts['medium'] += 1
            else:
                counts['low'] += 1
        return counts
    
    def save_redacted_document(self, redacted_text: str, original_filename: str,
                             output_dir: str, file_format: str = 'txt') -> str:
        """
        Save redacted document to file.
        
        Args:
            redacted_text (str): Redacted text content
            original_filename (str): Original filename
            output_dir (str): Output directory
            file_format (str): Output format ('txt' or 'pdf')
            
        Returns:
            str: Path to saved file
        """
        # Generate output filename
        base_name = os.path.splitext(original_filename)[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"{base_name}_redacted_{timestamp}.{file_format}"
        output_path = os.path.join(output_dir, output_filename)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        if file_format.lower() == 'txt':
            # Save as text file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"REDACTED DOCUMENT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Original: {original_filename}\n")
                f.write("-" * 50 + "\n\n")
                f.write(redacted_text)
        else:
            # For now, save as text even if PDF is requested
            # (avoiding external dependencies)
            output_path = output_path.replace('.pdf', '.txt')
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"REDACTED DOCUMENT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Original: {original_filename}\n")
                f.write("-" * 50 + "\n\n")
                f.write(redacted_text)
        
        return output_path
    
    def save_audit_trail(self, audit_trail: Dict, original_filename: str,
                        output_dir: str) -> str:
        """
        Save audit trail to JSON file.
        
        Args:
            audit_trail (Dict): Audit trail data
            original_filename (str): Original filename
            output_dir (str): Output directory
            
        Returns:
            str: Path to saved audit file
        """
        # Generate audit filename
        base_name = os.path.splitext(original_filename)[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        audit_filename = f"{base_name}_audit_{timestamp}.json"
        audit_path = os.path.join(output_dir, audit_filename)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Save audit trail
        with open(audit_path, 'w', encoding='utf-8') as f:
            json.dump(audit_trail, f, indent=2, ensure_ascii=False)
        
        return audit_path

