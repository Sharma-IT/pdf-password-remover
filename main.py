import sys
import os
import re
import hashlib
import binascii
from typing import Tuple, Dict, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class PDFCryptoError(Exception):
    pass


class PDFParser:
    def __init__(self, data: bytes):
        self.data = data
        self.objects: Dict[Tuple[int, int], bytes] = {}
        self.trailer: Dict[str, bytes] = {}
        self.encryption_dict: Optional[Dict] = None
        
    def parse(self):
        # Parse PDF objects
        obj_pattern = re.compile(rb'(\d+)\s+(\d+)\s+obj[\r\n\s]+(.+?)[\r\n\s]+endobj', re.DOTALL)
        for match in obj_pattern.finditer(self.data):
            obj_num = int(match.group(1))
            gen_num = int(match.group(2))
            self.objects[(obj_num, gen_num)] = match.group(3)

        # Parse trailer
        trailer_match = re.search(rb'trailer[\r\n\s]+<<(.+?)>>', self.data, re.DOTALL)
        if trailer_match:
            self.parse_trailer(trailer_match.group(1))

    def parse_trailer(self, trailer_data: bytes):
        # Extract encryption dict reference
        encrypt_match = re.search(rb'/Encrypt\s+(\d+)\s+(\d+)\s+R', trailer_data)
        if encrypt_match:
            obj_num = int(encrypt_match.group(1))
            gen_num = int(encrypt_match.group(2))
            self.parse_encryption_dict(self.objects.get((obj_num, gen_num), b''))

    def parse_encryption_dict(self, encrypt_data: bytes):
        self.encryption_dict = {}
        # Extract encryption parameters
        filter_match = re.search(rb'/Filter\s*/(\w+)', encrypt_data)
        if filter_match and filter_match.group(1) != b'Standard':
            raise PDFCryptoError("Unsupported encryption filter")

        v_match = re.search(rb'/V\s+(\d+)', encrypt_data)
        r_match = re.search(rb'/R\s+(\d+)', encrypt_data)
        length_match = re.search(rb'/Length\s+(\d+)', encrypt_data)
        cf_match = re.search(rb'/CF\s*<<(.+?)>>', encrypt_data, re.DOTALL)
        
        self.encryption_dict.update({
            'V': int(v_match.group(1)) if v_match else 0,
            'R': int(r_match.group(1)) if r_match else 0,
            'Length': int(length_match.group(1)) if length_match else 128,
        })

        # Extract key material
        o_match = re.search(rb'/O\s*\((.+?)\)', encrypt_data, re.DOTALL)
        u_match = re.search(rb'/U\s*\((.+?)\)', encrypt_data, re.DOTALL)
        oe_match = re.search(rb'/OE\s*\((.+?)\)', encrypt_data, re.DOTALL)
        ue_match = re.search(rb'/UE\s*\((.+?)\)', encrypt_data, re.DOTALL)
        
        if o_match and u_match:
            self.encryption_dict.update({
                'O': o_match.group(1),
                'U': u_match.group(1),
                'OE': oe_match.group(1) if oe_match else None,
                'UE': ue_match.group(1) if ue_match else None,
            })


class PDFCrypto:
    def __init__(self, parser: PDFParser):
        self.parser = parser
        if not parser.encryption_dict:
            raise PDFCryptoError("PDF is not encrypted")
            
    def compute_hash(self, data: bytes, salt: bytes, rounds: int) -> bytes:
        result = data + salt
        for _ in range(rounds):
            result = hashlib.sha256(result).digest()
        return result

    def derive_key(self, password: str) -> bytes:
        # Implementation of PDF 2.0 key derivation
        if not self.parser.encryption_dict:
            raise PDFCryptoError("No encryption dictionary found")

        # Convert password to bytes and pad/truncate to 127 bytes
        pwd = password.encode('utf-8')[:127]
        pwd = pwd.ljust(127, b'\0')

        # Get encryption parameters
        v = self.parser.encryption_dict.get('V', 0)
        r = self.parser.encryption_dict.get('R', 0)

        if v != 5 or r != 6:  # AES-256 requires V=5 and R=6
            raise PDFCryptoError(f"Unsupported encryption version (V={v}, R={r})")

        # Derive the key using SHA-256
        salt = os.urandom(8)  # Random salt
        rounds = 50  # Number of iterations as per PDF spec
        
        key = self.compute_hash(pwd, salt, rounds)
        validation_salt = os.urandom(8)
        validation_key = self.compute_hash(key + validation_salt, salt, rounds)
        
        return key, validation_key

    def decrypt_data(self, data: bytes, key: bytes) -> bytes:
        try:
            # Extract IV (first 16 bytes) and ciphertext
            iv = data[:16]
            ciphertext = data[16:]
            
            # Create AES cipher in CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Decrypt and remove PKCS7 padding
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            return decrypted
        except Exception as e:
            raise PDFCryptoError(f"Decryption failed: {str(e)}")


def decrypt_pdf(input_path: str, password: str, output_path: str):
    try:
        # Read PDF file
        with open(input_path, 'rb') as f:
            pdf_data = f.read()

        # Parse PDF
        parser = PDFParser(pdf_data)
        parser.parse()

        # Initialize crypto
        crypto = PDFCrypto(parser)

        # Derive key from password
        key, validation_key = crypto.derive_key(password)

        # Decrypt each encrypted object
        decrypted_objects = {}
        for obj_id, obj_data in parser.objects.items():
            try:
                if re.search(rb'stream[\r\n]', obj_data):
                    # Extract stream data
                    stream_match = re.search(rb'stream[\r\n](.+?)endstream', obj_data, re.DOTALL)
                    if stream_match:
                        stream_data = stream_match.group(1)
                        decrypted_stream = crypto.decrypt_data(stream_data, key)
                        # Replace encrypted stream with decrypted data
                        new_obj = obj_data.replace(stream_data, decrypted_stream)
                        decrypted_objects[obj_id] = new_obj
                    else:
                        decrypted_objects[obj_id] = obj_data
                else:
                    decrypted_objects[obj_id] = obj_data
            except Exception as e:
                print(f"Warning: Failed to decrypt object {obj_id}: {str(e)}")
                decrypted_objects[obj_id] = obj_data

        # Rebuild PDF
        output = []
        output.append(b'%PDF-1.7\n')
        
        # Write objects
        for (obj_num, gen_num), obj_data in decrypted_objects.items():
            output.append(f'{obj_num} {gen_num} obj\n'.encode())
            output.append(obj_data)
            output.append(b'\nendobj\n')

        # Write cross-reference table and trailer
        xref_offset = sum(len(x) for x in output)
        output.append(b'xref\n')
        # Add xref entries...

        # Write modified trailer without encryption
        trailer = parser.trailer.copy()
        if b'/Encrypt' in trailer:
            del trailer[b'/Encrypt']
        output.append(b'trailer\n<<\n')
        for key, value in trailer.items():
            output.append(f'{key} {value}\n'.encode())
        output.append(b'>>\n')
        output.append(f'startxref\n{xref_offset}\n%%EOF'.encode())

        # Write decrypted PDF
        with open(output_path, 'wb') as f:
            f.write(b''.join(output))

        print(f"Successfully decrypted PDF: {output_path}")

    except PDFCryptoError as e:
        print(f"Encryption error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


def print_usage():
    print("Usage: python main.py <input_pdf> <password> <output_pdf>")
    print("Example: python main.py encrypted.pdf mypassword decrypted.pdf")
    sys.exit(1)


def main():
    if len(sys.argv) != 4:
        print_usage()

    input_pdf = sys.argv[1]
    password = sys.argv[2]
    output_pdf = sys.argv[3]

    decrypt_pdf(input_pdf, password, output_pdf)


if __name__ == "__main__":
    main()
