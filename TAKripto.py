import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
from PIL.PngImagePlugin import PngInfo
import base64
import json
import os


# Fungsi tidak boleh kosong
def get_valid_input(prompt):
    while True:
        value = input(prompt).strip()
        if value:
            return value
        else:
            print("Input tidak boleh kosong. Silakan coba lagi.")


# Fungsi Hash
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Kunci AES
def save_key(key, filename="key.bin"):
    with open(filename, "wb") as file:
        file.write(key)


def load_key(filename="key.bin"):
    if os.path.exists(filename):
        with open(filename, "rb") as file:
            return file.read()
    return None


# Fungsi Caesar Cipher
def caesar_cipher_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char
    return encrypted_text


# Fungsi RC4
def rc4_encrypt(key, text):
    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in text:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(chr(ord(char) ^ K))

    return "".join(out)


# Fungsi AES
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ciphertext


def aes_decrypt(key, ciphertext):
    iv = ciphertext[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[AES.block_size :]), AES.block_size).decode()


# Fungsi Steganografi
def steganography_encrypt(image_path, message, output_path):
    img = Image.open(image_path)
    metadata = PngInfo()
    metadata.add_text("message", base64.b64encode(message.encode()).decode())
    img.save(output_path, "PNG", pnginfo=metadata)


def steganography_decrypt(image_path):
    img = Image.open(image_path)
    message = img.text.get("message")
    return base64.b64decode(message).decode()


# Fungsi penyimpanan data ke file JSON
def save_data(data, filename="data.json"):
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)


# Fungsi pembacaan data dari file JSON
def load_data(filename="data.json"):
    if os.path.exists(filename):
        with open(filename, "r") as file:
            return json.load(file)
    return {}


# Fungsi clear screen
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


# Fungsi Dekripsi Nama
def decrypt_name(encrypted_name_hex, aes_key):
    encrypted_name = bytes.fromhex(encrypted_name_hex)
    aes_decrypted = aes_decrypt(aes_key, encrypted_name)
    rc4_decrypted = rc4_encrypt("mysecretkey", aes_decrypted)
    return caesar_cipher_encrypt(rc4_decrypted, -3)


# Fungsi Dekripsi Semua Data
def decrypt_all_data(data, aes_key):
    decrypted_data = []
    for encrypted_name_hex, details in data.items():
        try:
            # Dekripsi nama
            name = decrypt_name(encrypted_name_hex, aes_key)

            # Dekripsi data lainnya
            encrypted_data = bytes.fromhex(details["encrypted_data"])
            aes_decrypted = aes_decrypt(aes_key, encrypted_data)
            rc4_decrypted = rc4_encrypt("mysecretkey", aes_decrypted)
            caesar_decrypted = caesar_cipher_encrypt(rc4_decrypted, -3)
            age, position = caesar_decrypted.split("|")

            decrypted_data.append(
                {
                    "name": name,
                    "age": age,
                    "position": position,
                }
            )
        except Exception as e:
            print(f"Kesalahan saat mendekripsi data: {e}")
    return decrypted_data


# Fungsi untuk menambah data tentara
def add_soldier(data, aes_key):
    clear_screen()
    name = get_valid_input("Masukkan nama tentara: ")
    age = get_valid_input("Masukkan umur tentara: ")
    position = get_valid_input("Masukkan jabatan tentara: ")
    password = get_valid_input("Masukkan password tentara: ")

    # Hash password
    hashed_password = hash_data(password)

    # Super-enkripsi data
    raw_data = f"{age}|{position}"
    caesar_encrypted_data = caesar_cipher_encrypt(raw_data, 3)
    rc4_encrypted_data = rc4_encrypt("mysecretkey", caesar_encrypted_data)
    aes_encrypted_data = aes_encrypt(aes_key, rc4_encrypted_data)

    # Super-enkripsi nama
    caesar_encrypted_name = caesar_cipher_encrypt(name, 3)
    rc4_encrypted_name = rc4_encrypt("mysecretkey", caesar_encrypted_name)
    aes_encrypted_name = aes_encrypt(aes_key, rc4_encrypted_name)

    # Simpan data
    data[aes_encrypted_name.hex()] = {
        "password": hashed_password,
        "encrypted_data": aes_encrypted_data.hex(),
    }
    save_data(data)
    print("Data tentara berhasil disimpan!")
    input("\nTekan Enter untuk kembali ke menu...")


# Menu Tentara
def soldier_menu(data, aes_key, name_hex):
    clear_screen()
    name = decrypt_name(name_hex, aes_key)
    print(f"--- Selamat Datang, {name} ---")
    print("1. Lihat Data Diri")
    print("2. Menu Steganografi")
    print("3. Keluar")
    choice = input("Pilih menu: ")

    if choice == "1":
        clear_screen()
        encrypted_data = bytes.fromhex(data[name_hex]["encrypted_data"])
        aes_decrypted = aes_decrypt(aes_key, encrypted_data)
        rc4_decrypted = rc4_encrypt("mysecretkey", aes_decrypted)
        caesar_decrypted = caesar_cipher_encrypt(rc4_decrypted, -3)
        age, position = caesar_decrypted.split("|")
        print(f"Nama: {name}")
        print(f"Umur: {age}")
        print(f"Jabatan: {position}")
        input("\nTekan Enter untuk kembali ke menu...")
    elif choice == "2":
        steganography_menu()
    elif choice == "3":
        return
    else:
        print("Pilihan tidak valid!")
        input("\nTekan Enter untuk mencoba lagi...")


# Menu Admin
def admin_menu(data, aes_key):
    while True:
        clear_screen()
        print("--- Admin Menu ---")
        print("1. Tambah Data Tentara")
        print("2. Lihat Semua Data (Terenkripsi)")
        print("3. Lihat Semua Data (Terdekripsi)")
        print("4. Keluar")
        choice = input("Pilih menu: ")

        if choice == "1":
            add_soldier(data, aes_key)
        elif choice == "2":
            clear_screen()
            print("Data Tentara (Terenkripsi):")
            for encrypted_name, details in data.items():
                print(f"Nama Terenkripsi: {encrypted_name}")
                print(f"Data Terenkripsi: {details['encrypted_data']}")
                print("=======================================")
            input("\nTekan Enter untuk kembali ke menu...")
        elif choice == "3":
            clear_screen()
            print("Data Tentara (Terdekripsi):")
            decrypted_data = decrypt_all_data(data, aes_key)
            for item in decrypted_data:
                print(f"Nama: {item['name']}")
                print(f"Umur: {item['age']}")
                print(f"Jabatan: {item['position']}")
                print("=======================================")
            input("\nTekan Enter untuk kembali ke menu...")
        elif choice == "4":
            break
        else:
            print("Pilihan tidak valid!")
            input("\nTekan Enter untuk mencoba lagi...")


# Fungsi Login Admin
def admin_login(data, aes_key):
    clear_screen()
    username = input("Masukkan username admin: ")
    password = input("Masukkan password admin: ")

    if username == "admin" and password == "admin":
        admin_menu(data, aes_key)
    else:
        print("Login gagal! Username atau password salah.")
        input("\nTekan Enter untuk kembali ke menu...")


# Menu Steganografi
def steganography_menu():
    while True:
        clear_screen()
        print("--- Steganografi Menu ---")
        print("1. Sisipkan Data ke Gambar")
        print("2. Baca Data dari Gambar")
        print("3. Kembali ke Menu Utama")
        choice = input("Pilih menu: ")

        if choice == "1":
            clear_screen()
            image_path = input("Masukkan path gambar asli (contoh: gambar.png): ")
            output_path = input(
                "Masukkan path gambar output (contoh: gambar_tersembunyi.png): "
            )
            message = input("Masukkan pesan yang akan disisipkan: ")
            steganography_encrypt(image_path, message, output_path)
            print("Pesan berhasil disisipkan ke dalam gambar!")
            input("\nTekan Enter untuk kembali ke menu...")
        elif choice == "2":
            clear_screen()
            image_path = input("Masukkan path gambar: ")
            message = steganography_decrypt(image_path)
            print(f"Pesan tersembunyi: {message}")
            input("\nTekan Enter untuk kembali ke menu...")
        elif choice == "3":
            break
        else:
            print("Pilihan tidak valid!")
            input("\nTekan Enter untuk mencoba lagi...")


# Menu Utama
def main():
    aes_key = load_key()
    if aes_key is None:
        aes_key = get_random_bytes(16)
        save_key(aes_key)

    data = load_data()

    while True:
        clear_screen()
        print("--- Sistem Tentara ---")
        print("1. Login Admin")
        print("2. Login Tentara")
        print("3. Keluar")
        choice = input("Pilih menu: ")

        if choice == "1":
            admin_login(data, aes_key)
        elif choice == "2":
            clear_screen()
            encrypted_name = input("Masukkan nama terenkripsi Anda: ")
            password = input("Masukkan password: ")

            if (
                encrypted_name in data
                and hash_data(password) == data[encrypted_name]["password"]
            ):
                soldier_menu(data, aes_key, encrypted_name)
            else:
                print("Login gagal! Nama atau password salah.")
                input("\nTekan Enter untuk kembali ke menu...")
        elif choice == "3":
            print("Terima kasih telah menggunakan sistem!")
            break
        else:
            print("Pilihan tidak valid!")
            input("\nTekan Enter untuk mencoba lagi...")


if __name__ == "__main__":
    main()
