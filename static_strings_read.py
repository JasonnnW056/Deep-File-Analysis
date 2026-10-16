import re
import sys

def extract_ascii(bytes_data: bytes, char_min_length: int= 6):
    pattern= rb"[\x20-\x7e]{%d,}" % char_min_length
    for d in re.finditer(pattern, bytes_data):
        yield d.start(), "ascii", d.group().decode("ascii")

def extract_utf_16le(bytes_data: bytes, char_min_length: int= 6):
    pattern= rb"(?:[\x20-\x7e]\x00){%d,}" % char_min_length
    for d in re.finditer(pattern, bytes_data):
        yield d.start(), "utf-16le", d.group().decode("utf-16le")

def main():
    if len(sys.argv)<2:
        print(f"To use this: python {sys.argv[0]} <file_path> [char_min_length] ")
        sys.exit(1)
        
    file_path= sys.argv[1]
    char_min_len= int(sys.argv[2]) if len(sys.argv)>2 else 6

    with open(file_path, "rb") as f:
        data= f.read()

    strings= list(extract_ascii(data, char_min_len)) + list(extract_utf_16le(data, char_min_len))
    strings.sort(key=lambda x:x[0])

    for offs, type, str in strings:
        print(f"0x{offs:08x} {type}: {str} ")
    print(f"{len(strings)} strings found")

if __name__ == "__main__":
    main()