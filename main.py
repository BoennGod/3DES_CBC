import time
import os
from PIL import Image
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

CHUNK_SIZE = 1024 * 1024
FILENAME = "resources/galaxy.jpg"

#check for weak keys
WEAK_KEYS = {
    # weak keys
    bytes.fromhex("0101010101010101"), bytes.fromhex("FEFEFEFEFEFEFEFE"), bytes.fromhex("E0E0E0E0F1F1F1F1"), bytes.fromhex("1F1F1F1F0E0E0E0E"),

    #semi weak keys
    bytes.fromhex("011F011F010E010E"), bytes.fromhex("1F011F010E010E01"), bytes.fromhex("01E001E001F101F1"), bytes.fromhex("E001E001F101F101"),
    bytes.fromhex("01FE01FE01FE01FE"), bytes.fromhex("FE01FE01FE01FE01"), bytes.fromhex("1FE01FE00EF10EF1"), bytes.fromhex("E01FE01FF10EF10E"),
    bytes.fromhex("1FFE1FFE0EFE0EFE"), bytes.fromhex("FE1FFE1FFE0EFE0E"), bytes.fromhex("E0FEE0FEF1FEF1FE"), bytes.fromhex("FEE0FEE0FEF1FEF1"),

    #possibly weak keys
    bytes.fromhex("01011F1F01010E0E"), bytes.fromhex("1F1F01010E0E0101"), bytes.fromhex("E0E01F1FF1F10E0E"), bytes.fromhex("0101E0E00101F1F1"),
    bytes.fromhex("1F1FE0E00E0EF1F1"), bytes.fromhex("E0E0FEFEF1F1FEFE"), bytes.fromhex("0101FEFE0101FEFE"), bytes.fromhex("1F1FFEFE0E0EFEFE"),
    bytes.fromhex("E0FE011FF1FE010E"), bytes.fromhex("011F1F01010E0E01"), bytes.fromhex("1FE001FE0EF101FE"), bytes.fromhex("E0FE1F01F1FE0E01"),
    bytes.fromhex("011FE0FE010EF1FE"), bytes.fromhex("1FE0E01F0EF1F10E"), bytes.fromhex("E0FEFEE0F1FEFEF1"), bytes.fromhex("011FFEE0010EFEF1"),
    bytes.fromhex("1FE0FE010EF1FE01"), bytes.fromhex("FE0101FEFE0101FE"), bytes.fromhex("01E01FFE01F10EFE"), bytes.fromhex("1FFE01E00EFE01F1"),
    bytes.fromhex("FE011FE0FE010EF1"), bytes.fromhex("FE01E01FFE01F10E"), bytes.fromhex("1FFEE0010EFEF101"), bytes.fromhex("FE1F01E0FE0E01F1"),
    bytes.fromhex("01E0E00101F1F101"), bytes.fromhex("1FFEFE1F0EFEFE0E"), bytes.fromhex("FE1FE001FE0EF101"), bytes.fromhex("01E0FE1F01F1FE0E"),
    bytes.fromhex("E00101E0F10101F1"), bytes.fromhex("FE1F1FFEFE0E0EFE"), bytes.fromhex("01FE1FE001FE0EF1"), bytes.fromhex("E0011FFEF1010EFE"),
    bytes.fromhex("FEE0011FFEF1010E"), bytes.fromhex("01FEE01F01FEF10E"), bytes.fromhex("E001FE1FF101FE0E"), bytes.fromhex("FEE01F01FEF10E01"),
    bytes.fromhex("01FEFE0101FEFE01"), bytes.fromhex("E01F01FEF10E01FE"), bytes.fromhex("FEE0E0FEFEF1F1FE"), bytes.fromhex("1F01011F0E01010E"),
    bytes.fromhex("E01F1FE0F10E0EF1"), bytes.fromhex("FEFE0101FEFE0101"), bytes.fromhex("1F01E0FE0E01F1FE"), bytes.fromhex("E01FFE01F10EFE01"),
    bytes.fromhex("FEFE1F1FFEFE0E0E"), bytes.fromhex("1F01FEE00E01FEF1"), bytes.fromhex("E0E00101F1F10101"), bytes.fromhex("FEFEE0E0FEFEF1F1"),
}

def generate_key_iv():
    while True:
        key = DES3.adjust_key_parity(get_random_bytes(24))
        k1 = key[:8]
        k2 = key[8:16]
        k3 = key[16:]

        if (k1 not in WEAK_KEYS and k2 not in WEAK_KEYS and k3 not in WEAK_KEYS and
                k1 != k2 and k2 != k3 and k1 != k3):
            break

    iv = get_random_bytes(8)
    return key, iv


def encrypt_file(input_path, output_path, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        chunk = infile.read(CHUNK_SIZE)

        while True:
            next_chunk = infile.read(CHUNK_SIZE)
            # pad the last chunk
            if len(next_chunk) == 0:
                chunk = pad(chunk, 8)
                outfile.write(cipher.encrypt(chunk))
                break

            # not last chunk
            outfile.write(cipher.encrypt(chunk))
            chunk = next_chunk


def decrypt_file(input_path, output_path, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    file_size = os.path.getsize(input_path)

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        processed = 0

        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break

            processed += len(chunk)
            decrypted = cipher.decrypt(chunk)
            if processed == file_size:
                decrypted = unpad(decrypted, 8)

            outfile.write(decrypted)


def show_image_if_possible(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    if ext in [".jpg", ".jpeg", ".png", ".bmp"]:
        try:
            img = Image.open(file_path)
            img.show()
            print("Image displayed.")
        except Exception as e:
            print("Could not display image:", e)


def main():
    input_file = FILENAME
    name, ext = os.path.splitext(input_file)
    encrypted_file = name + ".enc"
    decrypted_file = name + "_decrypted" + ext

    key, iv = generate_key_iv()

    print("Starting encryption...")
    start = time.perf_counter()
    encrypt_file(input_file, encrypted_file, key, iv)
    end = time.perf_counter()

    encryption_time = end - start
    print(f"Encryption time: {encryption_time:.2f} seconds")

    print("Starting decryption...")
    start = time.perf_counter()
    decrypt_file(encrypted_file, decrypted_file, key, iv)
    end = time.perf_counter()

    decryption_time = end - start
    print(f"Decryption time: {decryption_time:.2f} seconds")

    show_image_if_possible(decrypted_file)


if __name__ == "__main__":
    main()

