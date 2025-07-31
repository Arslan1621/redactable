from flask import Blueprint, request, jsonify, send_file
from src.simple_pii_detector import SimplePIIDetector
from src.simple_redaction_engine import SimpleRedactionEngine
import io
import datetime

redaction_bp = Blueprint("redaction", __name__)

# Initialize PII detector and Redaction Engine
pii_detector = SimplePIIDetector()
redaction_engine = SimpleRedactionEngine()

# In-memory store for processed documents (temporary for session)
# In a real production app, this would be a database or persistent storage
processed_documents = {}

@redaction_bp.route("/analyze", methods=["POST"])
def analyze_text():
    """Analyze text for PII without file upload"""
    try:
        data = request.get_json()
        
        if not data or "text" not in data:
            return jsonify({"error": "Text is required"}), 400
        
        text = data["text"]
        if not text.strip():
            return jsonify({"error": "Text cannot be empty"}), 400
        
        # Perform PII analysis
        pii_analysis = pii_detector.generate_redaction_suggestions(text)
        
        return jsonify({
            "success": True,
            "analysis": pii_analysis
        }), 200
        
    except Exception as e:
        print(f"Text analysis error: {e}")
        return jsonify({"error": "Internal server error during text analysis"}), 500

@redaction_bp.route("/preview", methods=["POST"])
def preview_redaction():
    """Preview text with selected redactions applied"""
    try:
        data = request.get_json()
        
        if not data or "text" not in data or "selected_detections" not in data:
            return jsonify({"error": "Text and selected_detections are required"}), 400
        
        text = data["text"]
        selected_detections = data["selected_detections"]
        redaction_options = data.get("redaction_options", {})
        
        if not text.strip():
            return jsonify({"error": "Text cannot be empty"}), 400
        
        # Apply redactions based on selected detections and options
        redacted_text = redaction_engine.apply_redactions(
            text, selected_detections, redaction_options
        )
        
        return jsonify({
            "success": True,
            "original_text": text,
            "redacted_text": redacted_text,
            "redactions_applied": len(selected_detections)
        }), 200
        
    except Exception as e:
        print(f"Redaction preview error: {e}")
        return jsonify({"error": "Internal server error during redaction preview"}), 500

@redaction_bp.route("/apply", methods=["POST"])
def apply_redaction():
    """Apply permanent redactions and make document available for download"""
    try:
        data = request.get_json()
        
        if not data or "file_id" not in data or "original_text" not in data or "selected_detections" not in data:
            return jsonify({"error": "file_id, original_text, and selected_detections are required"}), 400
        
        file_id = data["file_id"]
        original_text = data["original_text"]
        selected_detections = data["selected_detections"]
        redaction_options = data.get("redaction_options", {})
        original_filename = data.get("original_filename", "document.txt")

        if not original_text.strip():
            return jsonify({"error": "Original text cannot be empty"}), 400

        redacted_text = redaction_engine.apply_redactions(
            original_text, selected_detections, redaction_options
        )

        # Generate audit trail
        audit_trail = {
            "timestamp": datetime.datetime.now().isoformat(),
            "original_filename": original_filename,
            "redaction_options": redaction_options,
            "selected_detections": selected_detections,
            "redacted_length": len(redacted_text),
            "original_length": len(original_text)
        }

        # Store redacted content and audit trail in-memory for download
        processed_documents[file_id] = {
            "redacted_text": redacted_text,
            "audit_trail": audit_trail,
            "original_filename": original_filename
        }

        return jsonify({
            "success": True,
            "redaction_id": file_id,
            "redacted_text_preview": redacted_text[:200] + "..." if len(redacted_text) > 200 else redacted_text,
            "message": "Redaction applied and ready for download"
        }), 200

    except Exception as e:
        print(f"Apply redaction error: {e}")
        return jsonify({"error": "Internal server error during redaction application"}), 500

@redaction_bp.route("/download/<file_id>", methods=["GET"])
def download_redacted_document(file_id):
    """Download the redacted document"""
    try:
        if file_id not in processed_documents:
            return jsonify({"error": "Redacted document not found or expired"}), 404
        
        doc_data = processed_documents[file_id]
        redacted_text = doc_data["redacted_text"]
        original_filename = doc_data["original_filename"]

        # Create a file-like object in memory
        output = io.BytesIO(redacted_text.encode("utf-8"))
        output.seek(0)

        # Clean up the in-memory store after download (optional, but good for memory management)
        # del processed_documents[file_id]

        return send_file(
            output,
            mimetype="text/plain",
            as_attachment=True,
            download_name=f"redacted_{original_filename.replace(".txt", "").replace(".pdf", "")}_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.txt"
        )

    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({"error": "Internal server error during download"}), 500

@redaction_bp.route("/download_audit/<file_id>", methods=["GET"])
def download_audit_trail(file_id):
    """Download the audit trail for a redacted document"""
    try:
        if file_id not in processed_documents:
            return jsonify({"error": "Audit trail not found or expired"}), 404
        
        doc_data = processed_documents[file_id]
        audit_trail = doc_data["audit_trail"]
        original_filename = doc_data["original_filename"]

        # Create a file-like object in memory for the JSON audit trail
        output = io.BytesIO(jsonify(audit_trail).data)
        output.seek(0)

        return send_file(
            output,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"audit_{original_filename.replace(".txt", "").replace(".pdf", "")}_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.json"
        )

    except Exception as e:
        print(f"Audit download error: {e}")
        return jsonify({"error": "Internal server error during audit trail download"}), 500

@redaction_bp.route("/suggestions", methods=["POST"])
def get_redaction_suggestions():
    """Get intelligent redaction suggestions based on document type and content"""
    try:
        data = request.get_json()
        
        if not data or "text" not in data:
            return jsonify({"error": "Text is required"}), 400
        
        text = data["text"]
        document_type = data.get("document_type", "general")
        
        if not text.strip():
            return jsonify({"error": "Text cannot be empty"}), 400
        
        # Get PII analysis
        pii_analysis = pii_detector.generate_redaction_suggestions(text)
        
        # Generate context-aware suggestions
        smart_suggestions = redaction_engine.generate_smart_suggestions(pii_analysis, document_type, text)
        
        return jsonify({
            "success": True,
            "pii_analysis": pii_analysis,
            "smart_suggestions": smart_suggestions
        }), 200
        
    except Exception as e:
        print(f"Suggestions error: {e}")
        return jsonify({"error": "Internal server error during suggestion generation"}), 500



