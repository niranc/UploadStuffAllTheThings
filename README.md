# UploadStuffAllTheThings

Comprehensive file upload payload generator for security testing. Generates all possible payloads for SSRF, XXE, RCE, XSS, Path Traversal, and other vulnerabilities across all common file formats.

## Installation

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
./uploadallthethings <burp-collab>
```

Example:
```bash
./uploadallthethings abc123.burpcollaborator.net
```

## Supported File Formats

### Office Documents
- **PDF**: SSRF, XXE, RCE, XSS, Path Traversal
- **DOCX**: SSRF, XXE, RCE, XSS, Path Traversal
- **XLSX**: SSRF, XXE, RCE, XSS, Path Traversal
- **PPTX**: SSRF, XXE
- **ODT/ODS/ODP**: XXE

### Web Formats
- **HTML**: XSS, SSRF, RCE
- **SVG**: SSRF, XXE, RCE, XSS
- **XML**: XXE, XSS, Path Traversal

### Images
- **GIF**: SSRF, XXE (via XMP), XSS, Path Traversal
- **JPG**: SSRF, XSS, Path Traversal
- **PNG**: SSRF, XSS, Path Traversal

### Archives
- **ZIP**: XXE, Path Traversal, RCE (PHP)
- **JAR**: XXE, Path Traversal, RCE (PHP)
- **EPUB**: XXE

### Text Files
- **TXT**: XSS, SSRF, Path Traversal, RCE
- **CSV**: XSS, SSRF, Path Traversal, RCE
- **RTF**: SSRF, XSS, Path Traversal, RCE

## Directory Structure

The tool creates the following structure:
```
<extension>/
  ├── ssrf/
  │   └── payload_1.<ext>
  ├── xxe/
  │   └── payload_1.<ext>
  ├── rce/
  │   └── payload_1.<ext>
  ├── xss/
  │   └── payload_1.<ext>
  └── path_traversal/
      └── payload_1.<ext>
```

Example:
```
docx/
  ├── ssrf/
  │   ├── payload_1.docx
  │   └── payload_2.docx
  ├── xxe/
  │   ├── payload_1.docx
  │   ├── xxe_document.docx
  │   └── xxe_settings.docx
  ├── rce/
  │   └── payload_1.docx
  ├── xss/
  │   └── payload_1.docx
  └── path_traversal/
      └── payload_1.docx
```

## Vulnerabilities Covered

### SSRF (Server-Side Request Forgery)
- Direct URLs
- Protocol handlers (file://, gopher://, dict://, ldap://)
- IPv6 addresses
- Localhost bypasses
- URI actions in PDF
- External links in Office documents

### XXE (XML External Entity)
- Basic entity injection
- Parameter entities
- Out-of-band XXE
- XXE in all XML locations:
  - Office Open XML: workbook.xml, document.xml, sharedStrings.xml, styles.xml, settings.xml, core.xml, [Content_Types].xml, _rels/.rels
  - SVG, XML, ODT, ODS, ODP
  - XMP metadata in PDF/GIF

### RCE (Remote Code Execution)
- JavaScript in PDF (OpenAction, AA actions)
- Excel formulas (HYPERLINK, WEBSERVICE, FILTERXML, IMPORTXML, IMPORTDATA, IMPORTHTML, IMPORTFEED)
- Hyperlinks in DOCX
- SVG script execution
- HTML script execution
- Command injection in text files

### XSS (Cross-Site Scripting)
- Script tags
- Event handlers (onerror, onload, onfocus)
- SVG-based XSS
- HTML-based XSS
- JavaScript protocol handlers

### Path Traversal
- Directory traversal sequences (../, ..\\, ....//)
- URL encoding
- Windows and Linux paths
- In filenames and content

## Features

- **Comprehensive Coverage**: All major file formats and vulnerabilities
- **Organized Structure**: Easy-to-navigate directory hierarchy
- **Burp Integration**: All payloads target your Burp Collaborator instance
- **Extensible**: Easy to add new formats and vulnerabilities

## Notes

- This tool is for authorized security testing only
- Ensure you have permission before testing
- Generated files are for testing purposes
- Monitor your Burp Collaborator for successful payload execution

## Test Application

A web application is included in the `test-app/` directory to test uploaded files and view their rendered content.

### Running the Test Server

```bash
cd test-app
npm install
npm start
```

The server will be available at `http://localhost:3000`

Features:
- Upload files via drag & drop or file browser
- View uploaded files (images, PDFs, HTML, XML, etc.)
- Download or delete uploaded files
- Test all generated payloads for vulnerabilities

See `test-app/README.md` for more details.

## Contributing

Feel free to add new file formats or vulnerability types by creating new generator modules in the `generators/` directory.
