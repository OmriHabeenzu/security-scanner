import os
import hashlib
import magic
from werkzeug.utils import secure_filename
from flask import current_app

def allowed_file(filename):
    """Check if file extension is allowed"""
    if not filename:
        return False
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def get_file_hash(file_path, algorithm='sha256'):
    """Calculate file hash (MD5, SHA1, or SHA256)"""
    hash_algo = hashlib.new(algorithm)
    
    try:
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                hash_algo.update(chunk)
        return hash_algo.hexdigest()
    except Exception as e:
        return None

def get_file_type(file_path):
    """Detect file type using python-magic or fallback to extension"""
    try:
        import magic
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except ImportError:
        # Fallback if python-magic is not installed
        import mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or "application/octet-stream"
    except Exception:
        # Additional fallback to extension-based detection
        _, ext = os.path.splitext(file_path)
        extension_map = {
            '.exe': 'application/x-msdownload',
            '.dll': 'application/x-msdownload',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.txt': 'text/plain',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar-compressed',
            '.js': 'application/javascript',
            '.py': 'text/x-python'
        }
        return extension_map.get(ext.lower(), "application/octet-stream")

def get_file_size(file_path):
    """Get file size in bytes"""
    try:
        return os.path.getsize(file_path)
    except:
        return 0

def save_uploaded_file(file):
    """
    Save uploaded file securely and return file info
    Returns: dict with filepath, filename, hash, size, type
    """
    if not file or not allowed_file(file.filename):
        return None
    
    try:
        # Secure the filename
        filename = secure_filename(file.filename)
        
        # Create unique filename to prevent overwrites
        timestamp = hashlib.md5(str(os.urandom(16)).encode()).hexdigest()[:8]
        unique_filename = f"{timestamp}_{filename}"
        
        # Save file
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # Get file information
        file_info = {
            'filepath': filepath,
            'filename': filename,
            'unique_filename': unique_filename,
            'hash_md5': get_file_hash(filepath, 'md5'),
            'hash_sha256': get_file_hash(filepath, 'sha256'),
            'size': get_file_size(filepath),
            'type': get_file_type(filepath)
        }
        
        return file_info
    
    except Exception as e:
        print(f"Error saving file: {e}")
        return None

def delete_file(filepath):
    """Safely delete a file"""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
    except Exception as e:
        print(f"Error deleting file: {e}")
    return False

def format_file_size(size_bytes):
    """Convert bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"
