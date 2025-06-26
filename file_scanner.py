import os
import logging
import hashlib
import re
from datetime import datetime
from werkzeug.utils import secure_filename
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FileScanner:
    def __init__(self):
        self.scan_dir = os.path.join(os.path.dirname(__file__), 'scan_temp')
        os.makedirs(self.scan_dir, exist_ok=True)
        
        # Common malware signatures (MD5 hashes)
        self.malware_signatures = {
            'eicar': '44d88612fea8a8f36de82e1278abb02f',  # EICAR test file
            'test_virus': 'd41d8cd98f00b204e9800998ecf8427e'  # Example signature
        }
        
        # Suspicious patterns to look for
        self.suspicious_patterns = [
            rb'(?i)exec\s*\(',
            rb'(?i)eval\s*\(',
            rb'(?i)system\s*\(',
            rb'(?i)shell_exec\s*\(',
            rb'(?i)passthru\s*\(',
            rb'(?i)cmd\.exe',
            rb'(?i)bash\s*-c',
            rb'(?i)wget\s+http',
            rb'(?i)curl\s+http',
            rb'(?i)base64_decode',
            rb'(?i)document\.write\s*\(',
            rb'(?i)unescape\s*\(',
            rb'(?i)fromCharCode\s*\(',
            rb'(?i)String\.fromCharCode',
            rb'(?i)document\.location',
            rb'(?i)window\.location',
            rb'(?i)document\.cookie',
            rb'(?i)document\.domain',
            rb'(?i)document\.referrer',
            rb'(?i)document\.body',
            rb'(?i)document\.createElement',
            rb'(?i)document\.appendChild',
            rb'(?i)document\.insertBefore',
            rb'(?i)document\.write',
            rb'(?i)document\.writeln',
            rb'(?i)document\.open',
            rb'(?i)document\.close',
            rb'(?i)document\.getElementById',
            rb'(?i)document\.getElementsByTagName',
            rb'(?i)document\.getElementsByClassName',
            rb'(?i)document\.querySelector',
            rb'(?i)document\.querySelectorAll',
            rb'(?i)document\.addEventListener',
            rb'(?i)document\.removeEventListener',
            rb'(?i)document\.dispatchEvent',
            rb'(?i)document\.createEvent',
            rb'(?i)document\.createEventObject',
            rb'(?i)document\.createTextNode',
            rb'(?i)document\.createComment',
            rb'(?i)document\.createDocumentFragment',
            rb'(?i)document\.createAttribute',
            rb'(?i)document\.createNodeIterator',
            rb'(?i)document\.createTreeWalker',
            rb'(?i)document\.createRange',
            rb'(?i)document\.createExpression',
            rb'(?i)document\.createNSResolver',
            rb'(?i)document\.createEvent',
            rb'(?i)document\.createEventObject',
            rb'(?i)document\.createTextNode',
            rb'(?i)document\.createComment',
            rb'(?i)document\.createDocumentFragment',
            rb'(?i)document\.createAttribute',
            rb'(?i)document\.createNodeIterator',
            rb'(?i)document\.createTreeWalker',
            rb'(?i)document\.createRange',
            rb'(?i)document\.createExpression',
            rb'(?i)document\.createNSResolver'
        ]
        
    def scan_file(self, file):
        """
        Scan a file for potential malware, including ClamAV scan
        Returns: (bool, str) - (is_safe, message)
        """
        try:
            # Save the file temporarily
            filename = secure_filename(file.filename)
            filepath = os.path.join(self.scan_dir, filename)
            file.save(filepath)
            
            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                os.remove(filepath)
                return False, "File is too large (max 100MB)"
            
            clamav_message = None
            clamav_status = None
            # --- ClamAV scan ---
            try:
                result = subprocess.run([
                    'clamscan', '--no-summary', filepath
                ], capture_output=True, text=True, timeout=60)
                output = result.stdout.strip()
                if result.returncode == 1:
                    # Virus found
                    virus_name = None
                    # Try to extract virus name from output
                    if ": " in output:
                        parts = output.split(": ")
                        if len(parts) > 1:
                            virus_name = parts[1].replace("FOUND", "").strip()
                    clamav_message = f"ClamAV detected a virus: {virus_name or output}"
                    clamav_status = 'infected'
                    os.remove(filepath)
                    return False, f"{clamav_message}\nClamAV output: {output}"
                elif result.returncode == 2:
                    # Error running clamscan
                    clamav_message = f"ClamAV error: {result.stderr.strip()}"
                    clamav_status = 'error'
                    logger.error(clamav_message)
                elif result.returncode == 0:
                    # Clean
                    clamav_message = f"ClamAV scan clean. Output: {output}"
                    clamav_status = 'clean'
            except Exception as e:
                clamav_message = f"Error running ClamAV: {str(e)}"
                clamav_status = 'error'
                logger.error(clamav_message)
            
            # Calculate MD5 hash
            md5_hash = hashlib.md5()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5_hash.update(chunk)
            file_hash = md5_hash.hexdigest()
            
            # Check against known malware signatures
            if file_hash in self.malware_signatures.values():
                os.remove(filepath)
                return False, f"File matches known malware signature: {file_hash}\n{clamav_message or ''}"
            
            # Check for suspicious patterns
            with open(filepath, 'rb') as f:
                content = f.read()
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, content):
                        os.remove(filepath)
                        return False, f"Suspicious pattern detected: {pattern.decode()}\n{clamav_message or ''}"
            
            # Clean up
            os.remove(filepath)
            return True, f"File appears to be clean. {clamav_message or ''}"
            
        except Exception as e:
            logger.error(f"Error scanning file: {str(e)}")
            if 'filepath' in locals() and os.path.exists(filepath):
                os.remove(filepath)
            return False, f"Error scanning file: {str(e)}"
            
    def get_scanner_status(self):
        """Get the status of the scanner"""
        return {
            'status': 'online',
            'version': '1.0.0',
            'signatures': len(self.malware_signatures),
            'patterns': len(self.suspicious_patterns)
        } 