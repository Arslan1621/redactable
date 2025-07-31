import os
import uuid
from flask import Blueprint, request, jsonify
import PyPDF2
import io
from src.simple_pii_detector import SimplePIIDetector

documents_bp = Blueprint("documents", __name__)

# Configuration
ALLOWED_EXTENSIONS = {"pdf", "txt"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Initialize PII detector
pii_detector = SimplePIIDetector()

def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf_in_memory(file_stream):
    """Extract text from PDF file stream using PyPDF2"""
    text = ""
    try:
        pdf_reader = PyPDF2.PdfReader(file_stream)
        for page in pdf_reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
    except Exception as e:
        print(f"PDF extraction failed: {e}")
        return None
    return text.strip() if text.strip() else None

def extract_text_from_txt_in_memory(file_stream):
    """Extract text from TXT file stream"""
    try:
        text = file_stream.read().decode("utf-8")
        return text.strip() if text.strip() else None
    except UnicodeDecodeError:
        try:
            text = file_stream.read().decode("latin-1")
            return text.strip() if text.strip() else None
        except Exception as e:
            print(f"TXT extraction failed: {e}")
            return None
    except Exception as e:
        print(f"TXT extraction failed: {e}")
        return None

@documents_bp.route("/upload", methods=["POST"])
def upload_file():
    """Handle file upload and text extraction in-memory"""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files["file"]
        
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400
        
        if not allowed_file(file.filename):
            return jsonify({"error": "File type not supported"}), 400
        
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({"error": "File size exceeds 50MB limit"}), 400
        
        file_extension = file.filename.rsplit(".", 1)[1].lower()
        
        # Read file content into memory
        file_stream = io.BytesIO(file.read())
        
        extracted_text = None
        if file_extension == "pdf":
            extracted_text = extract_text_from_pdf_in_memory(file_stream)
        elif file_extension == "txt":
            extracted_text = extract_text_from_txt_in_memory(file_stream)
        
        pii_analysis = None
        if extracted_text:
            try:
                pii_analysis = pii_detector.generate_redaction_suggestions(extracted_text)
            except Exception as e:
                print(f"PII detection error: {e}")
                pii_analysis = {
                    "detections": [],
                    "summary": {"total_detections": 0, "by_type": {}, "high_confidence": 0, "medium_confidence": 0, "low_confidence": 0},
                    "suggestions": ["PII detection temporarily unavailable"]
                }
        
        response_data = {
            "success": True,
            "file_id": str(uuid.uuid4()), # Generate a unique ID for this in-memory session
            "original_filename": file.filename,
            "file_size": file_size,
            "file_type": file_extension,
            "extracted_text": extracted_text,
            "text_length": len(extracted_text) if extracted_text else 0,
            "has_text": bool(extracted_text),
            "pii_analysis": pii_analysis
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({"error": "Internal server error during file processing"}), 500

@documents_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "document-redaction-backend",
        "version": "1.0.0"
    }), 200

# Removed /files and /files/<file_id> endpoints as they rely on disk storage.

