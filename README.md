# PDF Password Remover
A comprehensive solution for removing passwords from PDF files, including support for AES-256 encryption.

## Features
- Supports AES-256 encrypted PDFs
- Handles both user and owner passwords
- Follows PDF 2.0 specification for encryption
- Detailed error reporting
- Preserves PDF structure and content

## Requirements
- Python 3.x
- PyCryptodome (for AES encryption)

## Installation
```bash
pip install -r requirements.txt
```

## Usage
Remove a password from a PDF file:
```bash
python main.py <input_pdf> <password> <output_pdf>
```

Arguments:
- `<input_pdf>`: Path to the encrypted PDF file
- `<password>`: The password for the PDF file
- `<output_pdf>`: Path to save the decrypted PDF file

## Example
```bash
python main.py encrypted.pdf mypassword decrypted.pdf
```

## Technical Details
This implementation:
- Supports PDF 2.0 encryption specification
- Implements AES-256 decryption
- Handles encryption dictionaries
- Preserves PDF object structure
- Properly manages stream decryption

## Limitations
- Only supports standard security handler
- Requires correct password for decryption
- May not support all PDF versions
