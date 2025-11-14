# UploadStuffAllTheThings

Outil de génération de payloads SSRF, XXE et RCE pour tous les formats de fichiers.

## Installation

```bash
pip3 install -r requirements.txt
```

## Utilisation

```bash
./uploadallthethings <burp-collab>
```

Exemple:
```bash
./uploadallthethings abc123.burpcollaborator.net
```

## Formats supportés

### PDF
- **SSRF**: URLs directes, URI actions, GoToR, Launch actions, annotations
- **XXE**: Via XMP metadata (toutes variantes)
- **RCE**: JavaScript dans OpenAction, AA (Additional Actions), app.alert, submitForm

### XLSX
- **SSRF**: URLs dans les cellules
- **XXE**: workbook.xml, sharedStrings.xml, styles.xml, [Content_Types].xml, worksheets/sheet1.xml, _rels/.rels
- **RCE**: HYPERLINK, WEBSERVICE, FILTERXML, IMPORTXML, IMPORTDATA, IMPORTHTML, IMPORTFEED

### DOCX
- **SSRF**: URLs dans le contenu, hyperliens
- **XXE**: document.xml, settings.xml, core.xml, [Content_Types].xml, footnotes.xml, header1.xml
- **RCE**: Hyperliens malveillants

### Autres formats
- **GIF**: SSRF, XXE (via XMP)
- **JPG**: SSRF (dans métadonnées)
- **SVG**: SSRF, XXE, RCE (onload, script tags)
- **PPTX**: XXE
- **ODT**: XXE
- **XML**: XXE (toutes variantes)
- **RTF**: SSRF (hyperliens)
- **ZIP**: XXE (fichiers XML dans archive)
- **EPUB**: XXE

## Structure des fichiers générés

L'outil crée les dossiers suivants:
- `pdf/` - Tous les payloads PDF
- `xlsx/` - Tous les payloads XLSX
- `docx/` - Tous les payloads DOCX
- `others/` - Tous les autres formats (GIF, SVG, etc.)

Chaque fichier est nommé selon le format: `<format>_<type>_<numéro>.<extension>`

Exemples:
- `pdf_ssrf_1.pdf`
- `xlsx_xxe_sharedstrings.xlsx`
- `docx_rce_1.docx`
- `svg_rce_1.svg`
