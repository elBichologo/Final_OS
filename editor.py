import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os

class TextEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Editor")
        self.text_area = tk.Text(self.root)
        self.text_area.pack(expand=True, fill='both')
        self.create_menu()
        
        if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
            self.load_keys()
        else:
            self.private_key, self.public_key = self.generate_keys()
            self.save_keys()

    def create_menu(self):
        menu_bar = tk.Menu(self.root)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_command(label="Save", command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menu_bar)

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def save_keys(self):
        with open("private_key.pem", "wb") as private_file:
            private_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open("public_key.pem", "wb") as public_file:
            public_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    def load_keys(self):
        with open("private_key.pem", "rb") as private_file:
            self.private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=None,
                backend=default_backend()
            )
        with open("public_key.pem", "rb") as public_file:
            self.public_key = serialization.load_pem_public_key(
                public_file.read(),
                backend=default_backend()
            )

    def encrypt(self, plaintext):
        ciphertext = self.public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def open_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            try:
                decrypted_data = self.decrypt(encrypted_data)
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(tk.END, decrypted_data)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt file: {e}")

    def save_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            plaintext = self.text_area.get(1.0, tk.END)
            encrypted_data = self.encrypt(plaintext)
            with open(file_path, 'wb') as file:
                file.write(encrypted_data)

if __name__ == "__main__":
    root = tk.Tk()
    editor = TextEditor(root)
    root.mainloop()