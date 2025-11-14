#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path

from generators.pdf_generator import generate_pdf_payloads
from generators.xlsx_generator import generate_xlsx_payloads
from generators.docx_generator import generate_docx_payloads
from generators.pptx_generator import generate_pptx_payloads
from generators.svg_generator import generate_svg_payloads
from generators.xml_generator import generate_xml_payloads
from generators.html_generator import generate_html_payloads
from generators.image_generator import generate_image_payloads
from generators.archive_generator import generate_archive_payloads
from generators.text_generator import generate_text_payloads
from generators.office_generator import generate_office_payloads

def main():
    parser = argparse.ArgumentParser(description='Generate all possible file upload payloads for security testing')
    parser.add_argument('burp_collab', help='Burp Collaborator URL (ex: abc123.burpcollaborator.net)')
    args = parser.parse_args()

    burp_collab = args.burp_collab
    print(f"[+] Generating payloads targeting: {burp_collab}")
    print("[+] Creating directory structure...\n")

    base_dir = Path.cwd()
    
    generators = {
        'pdf': (generate_pdf_payloads, None),
        'xlsx': (generate_xlsx_payloads, None),
        'docx': (generate_docx_payloads, None),
        'pptx': (generate_pptx_payloads, None),
        'svg': (generate_svg_payloads, None),
        'xml': (generate_xml_payloads, None),
        'html': (generate_html_payloads, None),
        'gif': (generate_image_payloads, 'gif'),
        'jpg': (generate_image_payloads, 'jpg'),
        'png': (generate_image_payloads, 'png'),
        'zip': (generate_archive_payloads, 'zip'),
        'jar': (generate_archive_payloads, 'jar'),
        'txt': (generate_text_payloads, 'txt'),
        'csv': (generate_text_payloads, 'csv'),
        'rtf': (generate_text_payloads, 'rtf'),
        'odt': (generate_office_payloads, None),
        'ods': (generate_office_payloads, None),
        'odp': (generate_office_payloads, None),
        'epub': (generate_archive_payloads, 'epub'),
    }

    try:
        for ext, (generator_func, ext_param) in generators.items():
            print(f"[+] Generating {ext.upper()} payloads...")
            ext_dir = base_dir / ext
            ext_dir.mkdir(exist_ok=True)
            
            if ext_param:
                generator_func(ext_dir, ext_param, burp_collab)
            else:
                generator_func(ext_dir, burp_collab)
            
            print(f"[✓] {ext.upper()} completed\n")

        print("[+] All payloads generated successfully!")
        print(f"[+] Files created in: {base_dir}")
        print(f"[+] Structure: <extension>/<vulnerability>/<payload_file>")
    except Exception as error:
        print(f"[!] Error during generation: {error}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
