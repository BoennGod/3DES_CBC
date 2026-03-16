import time
import os
from PIL import Image
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

CHUNK_SIZE = 1024 * 1024
FILENAME = "resources/galaxy.jpg"



def generate_key_iv():
    key = DES3.adjust_key_parity(get_random_bytes(24))
    iv = get_random_bytes(8) #for cbc
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

