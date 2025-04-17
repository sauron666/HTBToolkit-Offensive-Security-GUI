import os
import base64
import hashlib
import shutil
from typing import Union, Tuple, Optional

class FileOperations:
    @staticmethod
    def read_file(path: str, mode: str = 'r') -> Union[str, bytes]:
        """
        Read file content with error handling
        
        Args:
            path: Path to file
            mode: Read mode ('r' for text, 'rb' for binary)
            
        Returns:
            File content as string or bytes, or error message
        """
        try:
            with open(path, mode) as f:
                return f.read()
        except PermissionError:
            return f"[!] Permission denied: {path}"
        except FileNotFoundError:
            return f"[!] File not found: {path}"
        except IsADirectoryError:
            return f"[!] Path is a directory: {path}"
        except Exception as e:
            return f"[!] Error reading {path}: {str(e)}"

    @staticmethod
    def write_file(path: str, content: Union[str, bytes], mode: str = 'w') -> str:
        """
        Write content to file with error handling
        
        Args:
            path: Path to file
            content: Content to write
            mode: Write mode ('w' for text, 'wb' for binary)
            
        Returns:
            Success message or error message
        """
        try:
            with open(path, mode) as f:
                f.write(content)
            return f"[+] Successfully wrote to {path}"
        except PermissionError:
            return f"[!] Permission denied: {path}"
        except IsADirectoryError:
            return f"[!] Path is a directory: {path}"
        except Exception as e:
            return f"[!] Error writing to {path}: {str(e)}"

    @staticmethod
    def delete_file(path: str) -> str:
        """
        Delete a file with error handling
        
        Args:
            path: Path to file
            
        Returns:
            Success message or error message
        """
        try:
            os.remove(path)
            return f"[+] Successfully deleted {path}"
        except PermissionError:
            return f"[!] Permission denied: {path}"
        except FileNotFoundError:
            return f"[!] File not found: {path}"
        except IsADirectoryError:
            return f"[!] Path is a directory: {path}"
        except Exception as e:
            return f"[!] Error deleting {path}: {str(e)}"

    @staticmethod
    def change_permissions(path: str, mode: str) -> str:
        """
        Change file permissions (Unix-like systems)
        
        Args:
            path: Path to file
            mode: Permission mode (e.g. '755', '644')
            
        Returns:
            Success message or error message
        """
        try:
            os.chmod(path, int(mode, 8))
            return f"[+] Changed permissions of {path} to {mode}"
        except PermissionError:
            return f"[!] Permission denied: {path}"
        except FileNotFoundError:
            return f"[!] File not found: {path}"
        except Exception as e:
            return f"[!] Error changing permissions: {str(e)}"

    @staticmethod
    def generate_base64_payload(path: str) -> str:
        """
        Generate base64 encoded file content
        
        Args:
            path: Path to file
            
        Returns:
            Base64 encoded string or error message
        """
        try:
            with open(path, 'rb') as f:
                encoded = base64.b64encode(f.read()).decode('utf-8')
            return encoded
        except Exception as e:
            return f"[!] Error generating base64: {str(e)}"

    @staticmethod
    def decode_base64_to_file(encoded_str: str, output_path: str) -> str:
        """
        Decode base64 string to file
        
        Args:
            encoded_str: Base64 encoded string
            output_path: Path to save decoded file
            
        Returns:
            Success message or error message
        """
        try:
            with open(output_path, 'wb') as f:
                f.write(base64.b64decode(encoded_str))
            return f"[+] Successfully decoded to {output_path}"
        except Exception as e:
            return f"[!] Error decoding base64: {str(e)}"

    @staticmethod
    def calculate_hashes(path: str) -> Union[dict, str]:
        """
        Calculate multiple hash digests for a file
        
        Args:
            path: Path to file
            
        Returns:
            Dictionary of hash types and values, or error message
        """
        try:
            hashes = {
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1(),
                'sha256': hashlib.sha256(),
                'sha512': hashlib.sha512()
            }
            
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
        except FileNotFoundError:
            return f"[!] File not found: {path}"
        except PermissionError:
            return f"[!] Permission denied: {path}"
        except Exception as e:
            return f"[!] Error calculating hashes: {str(e)}"

    @staticmethod
    def upload_file(local_path: str, remote_url: str, param_name: str = 'file') -> str:
        """
        Upload file to remote server via HTTP POST
        
        Args:
            local_path: Path to local file
            remote_url: URL to upload to
            param_name: Form parameter name
            
        Returns:
            Server response or error message
        """
        try:
            import requests
            with open(local_path, 'rb') as f:
                files = {param_name: (os.path.basename(local_path), f}
                response = requests.post(remote_url, files=files)
                return f"[+] Upload response ({response.status_code}): {response.text[:200]}"
        except Exception as e:
            return f"[!] Error uploading file: {str(e)}"

    @staticmethod
    def download_file(url: str, local_path: str) -> str:
        """
        Download file from URL
        
        Args:
            url: File URL to download
            local_path: Path to save file
            
        Returns:
            Success message or error message
        """
        try:
            import requests
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return f"[+] Successfully downloaded to {local_path}"
        except Exception as e:
            return f"[!] Error downloading file: {str(e)}"

    @staticmethod
    def find_files(directory: str, pattern: str = '*', recursive: bool = True) -> Union[list, str]:
        """
        Find files matching pattern in directory
        
        Args:
            directory: Directory to search
            pattern: File pattern to match (e.g., '*.txt')
            recursive: Search recursively
            
        Returns:
            List of matching files or error message
        """
        try:
            import fnmatch
            matches = []
            if recursive:
                for root, _, filenames in os.walk(directory):
                    for filename in fnmatch.filter(filenames, pattern):
                        matches.append(os.path.join(root, filename))
            else:
                matches = fnmatch.filter(os.listdir(directory), pattern)
                matches = [os.path.join(directory, f) for f in matches]
            return matches
        except Exception as e:
            return f"[!] Error finding files: {str(e)}"

    @staticmethod
    def find_sensitive_files(directory: str = '.', extensions: list = None) -> Union[list, str]:
        """
        Find potentially sensitive files
        
        Args:
            directory: Directory to search
            extensions: List of file extensions to look for
            
        Returns:
            List of sensitive files or error message
        """
        if extensions is None:
            extensions = ['.env', '.pem', '.key', '.secret', '.cfg', '.conf', '.bak', '.sql', '.log']
        
        try:
            sensitive_files = []
            for root, _, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in extensions):
                        sensitive_files.append(os.path.join(root, file))
            return sensitive_files
        except Exception as e:
            return f"[!] Error finding sensitive files: {str(e)}"

    @staticmethod
    def check_file_permissions(path: str) -> Union[dict, str]:
        """
        Check file permissions and ownership
        
        Args:
            path: Path to file
            
        Returns:
            Dictionary with permission info or error message
        """
        try:
            stat = os.stat(path)
            return {
                'readable': os.access(path, os.R_OK),
                'writable': os.access(path, os.W_OK),
                'executable': os.access(path, os.X_OK),
                'uid': stat.st_uid,
                'gid': stat.st_gid,
                'mode': oct(stat.st_mode)[-3:]
            }
        except Exception as e:
            return f"[!] Error checking permissions: {str(e)}"

    @staticmethod
    def create_archive(source_path: str, archive_path: str, format: str = 'zip') -> str:
        """
        Create archive of files/directory
        
        Args:
            source_path: Path to file/directory to archive
            archive_path: Output archive path
            format: Archive format ('zip', 'tar', 'gztar', 'bztar', 'xztar')
            
        Returns:
            Success message or error message
        """
        try:
            import shutil
            shutil.make_archive(
                os.path.splitext(archive_path)[0],
                format,
                os.path.dirname(source_path),
                os.path.basename(source_path)
            )
            return f"[+] Created archive at {archive_path}"
        except Exception as e:
            return f"[!] Error creating archive: {str(e)}"

    @staticmethod
    def extract_archive(archive_path: str, extract_dir: str = None) -> str:
        """
        Extract archive file
        
        Args:
            archive_path: Path to archive file
            extract_dir: Directory to extract to (default: same directory)
            
        Returns:
            Success message or error message
        """
        try:
            import shutil
            if extract_dir is None:
                extract_dir = os.path.dirname(archive_path)
            shutil.unpack_archive(archive_path, extract_dir)
            return f"[+] Extracted to {extract_dir}"
        except Exception as e:
            return f"[!] Error extracting archive: {str(e)}"

    @staticmethod
    def monitor_file_changes(path: str, interval: int = 5) -> str:
        """
        Monitor file for changes (size, modification time)
        
        Args:
            path: Path to file to monitor
            interval: Check interval in seconds
            
        Returns:
            Continuous monitoring output or error message
        """
        try:
            import time
            last_size = os.path.getsize(path)
            last_mtime = os.path.getmtime(path)
            
            while True:
                current_size = os.path.getsize(path)
                current_mtime = os.path.getmtime(path)
                
                if current_size != last_size or current_mtime != last_mtime:
                    yield f"[+] File changed - Size: {current_size} bytes, Modified: {time.ctime(current_mtime)}"
                    last_size = current_size
                    last_mtime = current_mtime
                
                time.sleep(interval)
        except Exception as e:
            return f"[!] Error monitoring file: {str(e)}"
