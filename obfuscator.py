import random
import base64
from typing import Dict

class CodeObfuscator:
    @staticmethod
    def obfuscate_powershell(code: str) -> str:
        """
        Obfuscate PowerShell code using multiple techniques
        
        Args:
            code: Original PowerShell code
            
        Returns:
            str: Obfuscated code
        """
        # Randomize variable names
        var_map = {}
        for var in set([word for word in code.split() if word.startswith('$')]):
            var_map[var] = f'${"".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))}'
        
        for old, new in var_map.items():
            code = code.replace(old, new)
        
        # Add junk code
        junk_code = [
            f'${"".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))} = {random.randint(1,100)}',
            'Start-Sleep -Milliseconds 100',
            f'[System.Net.Dns]::GetHostByName("{".".join(str(random.randint(0,255)) for _ in range(4))}")'
        ]
        
        insert_pos = random.randint(0, len(code.split('\n'))-1)
        lines = code.split('\n')
        lines.insert(insert_pos, random.choice(junk_code))
        code = '\n'.join(lines)
        
        # Base64 encode parts
        parts = code.split(';')
        for i in range(len(parts)):
            if len(parts[i]) > 20 and not parts[i].strip().startswith('#'):
                parts[i] = f"iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{base64.b64encode(parts[i].encode()).decode()}')))"
        
        return ';'.join(parts)

    @staticmethod
    def obfuscate_vba(code: str) -> str:
        """
        Obfuscate VBA macro code
        
        Args:
            code: Original VBA code
            
        Returns:
            str: Obfuscated code
        """
        # Replace strings with Chr() concatenation
        lines = []
        for line in code.split('\n'):
            if '"' in line:
                parts = line.split('"')
                for i in range(1, len(parts), 2):
                    if parts[i].strip():
                        chr_parts = '+'.join([f'Chr({ord(c)})' for c in parts[i]])
                        parts[i] = f'& {chr_parts} &'
                line = '"'.join(parts)
            lines.append(line)
        
        # Randomize function names
        func_map = {}
        for word in set([w for w in code.split() if w.startswith('Function') or w.startswith('Sub')]):
            func_map[word] = word.split()[0] + ' ' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10))
        
        for old, new in func_map.items():
            code = code.replace(old, new)
        
        return '\n'.join(lines)

    @staticmethod
    def obfuscate_bash(code: str) -> str:
        """
        Obfuscate bash shell commands
        
        Args:
            code: Original bash code
            
        Returns:
            str: Obfuscated code
        """
        # Base64 encode
        if ' ' not in code.strip() and ';' not in code.strip():
            encoded = base64.b64encode(code.encode()).decode()
            return f'echo {encoded} | base64 -d | bash'
        
        # Replace with variable expansion
        parts = code.split()
        for i in range(len(parts)):
            if len(parts[i]) > 3 and not parts[i].startswith('-'):
                var = f'_{i}'
                code = code.replace(parts[i], f'${{{var}}}')
                code = f'{var}={parts[i]}; {code}'
        
        return code

    @staticmethod
    def get_obfuscators() -> Dict[str, callable]:
        """
        Get all available obfuscation methods
        
        Returns:
            dict: Mapping of language to obfuscator function
        """
        return {
            'powershell': CodeObfuscator.obfuscate_powershell,
            'vba': CodeObfuscator.obfuscate_vba,
            'bash': CodeObfuscator.obfuscate_bash
        }
