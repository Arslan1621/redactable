import os
import uuid
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
import PyPDF2
from src.simple_pii_detector import SimplePIIDetector

documents_bp = Blueprint('documents', __name__)

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'txt'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Initialize PII detector
pii_detector = SimplePIIDetector()

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(file_path):
    """Extract text from PDF using PyPDF2"""
    text = ""
    
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for page in pdf_reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        print(f"PDF extraction failed: {e}")
        return None
    
    return text.strip() if text.strip() else None

def extract_text_from_txt(file_path):
    """Extract text from TXT file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            text = file.read()
        return text.strip() if text.strip() else None
    except UnicodeDecodeError:
        # Try with different encoding
        try:
            with open(file_path, 'r', encoding='latin-1') as file:
                text = file.read()
            return text.strip() if text.strip() else None
        except Exception as e:
            print(f"TXT extraction failed: {e}")
            return None
    except Exception as e:
        print(f"TXT extraction failed: {e}")
        return None

def extract_text_from_file(file_path, file_type):
    """Extract text based on file type"""
    file_type = file_type.lower()
    
    if file_type == 'pdf':
        return extract_text_from_pdf(file_path)
    elif file_type == 'txt':
        return extract_text_from_txt(file_path)
    else:
        return "File type not supported for text extraction"

@documents_bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and text extraction"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not supported'}), 400
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({'error': 'File size exceeds 50MB limit'}), 400
        
        # Generate unique filename
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Save file
        file.save(file_path)
        
        # Extract text
        extracted_text = extract_text_from_file(file_path, file_extension)
        
        # Perform PII detection if text was extracted
        pii_analysis = None
        if extracted_text:
            try:
                pii_analysis = pii_detector.generate_redaction_suggestions(extracted_text)
            except Exception as e:
                print(f"PII detection error: {e}")
                pii_analysis = {
                    'detections': [],
                    'summary': {'total_detections': 0, 'by_type': {}, 'high_confidence': 0, 'medium_confidence': 0, 'low_confidence': 0},
                    'suggestions': ['PII detection temporarily unavailable']
                }
        
        # Prepare response
        response_data = {
            'success': True,
            'file_id': unique_filename,
            'original_filename': file.filename,
            'file_size': file_size,
            'file_type': file_extension,
            'extracted_text': extracted_text,
            'text_length': len(extracted_text) if extracted_text else 0,
            'has_text': bool(extracted_text),
            'pii_analysis': pii_analysis
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'error': 'Internal server error during file processing'}), 500

@documents_bp.route('/files', methods=['GET'])
def list_files():
    """List all uploaded files"""
    try:
        files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(file_path):
                file_stats = os.stat(file_path)
                files.append({
                    'file_id': filename,
                    'file_size': file_stats.st_size,
                    'upload_time': file_stats.st_mtime
                })
        
        return jsonify({'files': files}), 200
        
    except Exception as e:
        print(f"List files error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@documents_bp.route('/files/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a specific file"""
    try:
        file_path = os.path.join(UPLOAD_FOLDER, secure_filename(file_id))
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        os.remove(file_path)
        return jsonify({'success': True, 'message': 'File deleted successfully'}), 200
        
    except Exception as e:
        print(f"Delete file error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@documents_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'document-redaction-backend',
        'version': '1.0.0'
    }), 200

