import os
import subprocess
import platform
import shlex
from typing import Union, Dict, List

class ShellTools:
    @staticmethod
    def run_command(cmd: str, timeout: int = 30) -> str:
        """Execute system command safely with timeout"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    cmd, 
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                args = shlex.split(cmd)
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            return result.stdout + (f"\n[stderr]\n{result.stderr}" if result.stderr else "")
        except subprocess.TimeoutExpired:
            return "[!] Command timed out"
        except Exception as e:
            return f"[!] Command execution error: {str(e)}"

    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get detailed system information"""
        info = {
            "OS": platform.system(),
            "OS Version": platform.version(),
            "Architecture": platform.machine(),
            "User": os.getenv("USER") or os.getenv("USERNAME"),
            "Hostname": platform.node(),
            "Python Version": platform.python_version(),
            "CPU Cores": str(os.cpu_count()),
            "Current Directory": os.getcwd()
        }
        return info

    @staticmethod
    def list_directory(path: str = ".") -> Union[List[str], str]:
        """List directory contents safely"""
        try:
            return os.listdir(path)
        except Exception as e:
            return f"[!] Error listing directory: {str(e)}"

    @staticmethod
    def current_user() -> str:
        """Get current user with whoami"""
        return ShellTools.run_command("whoami")

    @staticmethod
    def network_info() -> str:
        """Get network information"""
        if platform.system() == "Windows":
            return ShellTools.run_command("ipconfig /all")
        else:
            return ShellTools.run_command("ifconfig || ip a")

    @staticmethod
    def running_processes() -> str:
        """Get running processes"""
        if platform.system() == "Windows":
            return ShellTools.run_command("tasklist /V")
        else:
            return ShellTools.run_command("ps aux")

    @staticmethod
    def file_permissions(path: str) -> str:
        """Get file permissions"""
        try:
            if platform.system() == "Windows":
                return ShellTools.run_command(f"icacls \"{path}\"")
            else:
                stat = os.stat(path)
                return f"Mode: {oct(stat.st_mode)}\nOwner: {stat.st_uid}\nGroup: {stat.st_gid}"
        except Exception as e:
            return f"[!] Error getting permissions: {str(e)}"

    @staticmethod
    def check_tools_installed(tools: List[str]) -> Dict[str, bool]:
        """Check if required tools are installed"""
        results = {}
        for tool in tools:
            results[tool] = ShellTools.is_tool_installed(tool)
        return results

    @staticmethod
    def is_tool_installed(tool: str) -> bool:
        """Check if a specific tool is installed"""
        try:
            if platform.system() == "Windows":
                cmd = f"where {tool}"
            else:
                cmd = f"command -v {tool}"
            
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return result.returncode == 0
        except Exception:
            return False
