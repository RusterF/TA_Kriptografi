import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
from PIL.PngImagePlugin import PngInfo
import base64
import json
import os


# Fungsi Hash
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()


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


# Tambahkan fungsi clear screen
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


# Fungsi soldier_login dengan clear screen
def soldier_login(data):
    clear_screen()
    print("--- Login Tentara ---")
    username = input("Masukkan nama tentara: ")
    hashed_username = hash_data(username)

    if hashed_username in data:
        # Dekripsi data terenkripsi
        try:
            aes_key = get_random_bytes(16)  # Pastikan kunci AES sama saat penyimpanan
            encrypted_data = bytes.fromhex(data[hashed_username]["encrypted_data"])
            aes_decrypted = aes_decrypt(aes_key, encrypted_data)

            # Reverse Super Encryption (RC4 + Caesar)
            rc4_decrypted = rc4_encrypt("mysecretkey", aes_decrypted)  # RC4 dekripsi
            decrypted_data = caesar_cipher_encrypt(rc4_decrypted, -3)

            # Pisahkan data asli
            name, age, position = decrypted_data.split("|")

            print("Data Anda:")
            print(f"Nama: {name}")
            print(f"Umur: {age}")
            print(f"Jabatan: {position}")
        except Exception as e:
            print("Kesalahan saat mendekripsi data:", e)
    else:
        print("Data tidak ditemukan!")

    input("\nTekan Enter untuk kembali ke menu...")  # Tunggu input
    clear_screen()


# Fungsi admin menu
def admin_menu(data):
    print("Data Tentara:")
    for hashed_username, details in data.items():
        print(f"Nama (Hashed): {hashed_username}")
        print(f"Umur: {details['age']}")
        print(f"Jabatan: {details['position']}")
        print("=======================================")


# Fungsi Dekripsi Data oleh Admin
def decrypt_data(data, aes_key):
    for hashed_username, details in data.items():
        try:
            encrypted_data = bytes.fromhex(details["encrypted_data"])
            aes_decrypted = aes_decrypt(aes_key, encrypted_data)

            # Reverse Super Encryption (RC4 + Caesar)
            rc4_decrypted = rc4_encrypt(
                "mysecretkey", aes_decrypted
            )  # RC4 dekripsi menggunakan kunci yang sama
            caesar_decrypted = caesar_cipher_encrypt(rc4_decrypted, -3)

            print(f"Nama (Hashed): {hashed_username}")
            print(f"Data Terdekripsi: {caesar_decrypted}")
            print("=======================================")
        except Exception as e:
            print(f"Kesalahan saat mendekripsi data untuk {hashed_username}: {e}")


# Fungsi admin_menu dengan clear screen
def admin_menu(data, aes_key):
    while True:
        clear_screen()
        print("--- Admin Menu ---")
        print("1. Lihat Semua Data (Terenkripsi)")
        print("2. Dekripsi dan Lihat Data")
        print("3. Kembali ke Menu Utama")
        choice = input("Pilih menu: ")

        if choice == "1":
            clear_screen()
            print("Data Tentara (Terenkripsi):")
            for hashed_username, details in data.items():
                print(f"Nama (Hashed): {hashed_username}")
                print(f"Data Terenkripsi: {details['encrypted_data']}")
                print("=======================================")
            input("\nTekan Enter untuk kembali ke menu...")  # Tunggu input
        elif choice == "2":
            clear_screen()
            print("Dekripsi Data:")
            decrypt_data(data, aes_key)
            input("\nTekan Enter untuk kembali ke menu...")  # Tunggu input
        elif choice == "3":
            clear_screen()
            break
        else:
            print("Pilihan tidak valid! Silakan coba lagi.")
            input("\nTekan Enter untuk mencoba lagi...")  # Tunggu input


# Fungsi steganography_menu dengan clear screen
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
            message = input("Masukkan data yang ingin disisipkan: ")

            try:
                steganography_encrypt(image_path, message, output_path)
                print(f"Data berhasil disisipkan ke gambar: {output_path}")
            except Exception as e:
                print(f"Terjadi kesalahan: {e}")
            input("\nTekan Enter untuk kembali ke menu...")  # Tunggu input
        elif choice == "2":
            clear_screen()
            image_path = input("Masukkan path gambar yang ingin dibaca: ")

            try:
                message = steganography_decrypt(image_path)
                print(f"Data tersembunyi di gambar: {message}")
            except Exception as e:
                print(f"Terjadi kesalahan: {e}")
            input("\nTekan Enter untuk kembali ke menu...")  # Tunggu input
        elif choice == "3":
            clear_screen()
            break
        else:
            print("Pilihan tidak valid! Silakan coba lagi.")
            input("\nTekan Enter untuk mencoba lagi...")  # Tunggu input


# Fungsi main dengan clear screen
def main():
    data = load_data()
    aes_key = get_random_bytes(16)  # Kunci AES untuk mengenkripsi data baru

    while True:
        clear_screen()
        print("--- Sistem Pengamanan Data Tentara ---")
        print("1. Tambah Data Tentara")
        print("2. Login Tentara")
        print("3. Admin Menu")
        print("4. Menu Steganografi")
        print("5. Keluar")
        choice = input("Pilih menu: ")

        if choice == "1":
            clear_screen()
            name = input("Masukkan nama: ")
            age = input("Masukkan umur: ")
            position = input("Masukkan jabatan: ")

            # Enkripsi dan simpan data
            raw_data = f"{name}|{age}|{position}"
            hashed_name = hash_data(name)
            caesar_encrypted = caesar_cipher_encrypt(raw_data, 3)
            rc4_encrypted = rc4_encrypt("mysecretkey", caesar_encrypted)
            aes_encrypted = aes_encrypt(aes_key, rc4_encrypted)

            # Simpan hanya ciphertext
            data[hashed_name] = {
                "encrypted_data": aes_encrypted.hex(),
            }
            save_data(data)
            print("Data tentara berhasil disimpan!")
            input("\nTekan Enter untuk kembali ke menu...")  # Tunggu input

        elif choice == "2":
            soldier_login(data)

        elif choice == "3":
            admin_menu(data, aes_key)

        elif choice == "4":
            steganography_menu()

        elif choice == "5":
            clear_screen()
            print("Keluar dari sistem...")
            break

        else:
            print("Pilihan tidak valid! Silakan coba lagi.")
            input("\nTekan Enter untuk mencoba lagi...")  # Tunggu input


if __name__ == "__main__":
    main()
