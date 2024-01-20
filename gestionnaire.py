import tkinter as tk
from tkinter import messagebox, Listbox, Scrollbar, Toplevel
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip

class PasswordManager:
    def __init__(self):
        self.app = tk.Tk()
        self.app.title(".")
        self.app.geometry(f"{180}x{200}")

        self.password_list = Listbox(self.app)
        self.password_list.pack()

        self.password_list.bind("<Double-1>",self.get_password)

        self.new_password_button = tk.Button(self.app, text="Nouveau mot de passe", command=self.create_new_password_window)
        self.new_password_button.pack(pady=5,padx=5)

        self.show_passwords()

    # Fonction pour générer un mot de passe aléatoire de 128 bits en base64
    def generate_password(self):
        key = Fernet.generate_key()
        password = base64.urlsafe_b64encode(key).decode()
        self.new_password_entry.delete(0, tk.END)
        self.new_password_entry.insert(0, password)

    # Fonction pour enregistrer le mot de passe chiffré avec PBKDF2
    def save_password(self):
        site = self.site_entry.get()
        password = self.password_entry.get()
        master_password = self.master_password_entry.get()

        if site and password and master_password:
            salt = b'salt'  # Vous devriez générer un sel unique pour chaque mot de passe
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                iterations=100000,
                salt=salt,
                length=32,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

            fernet = Fernet(key)
            encrypted_password = fernet.encrypt(password.encode()).decode()

            with open("passwords.txt", "a") as file:
                file.write(f"Site: {site}, Password: {encrypted_password}\n")
            self.site_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            messagebox.showinfo("Success", "Mot de passe enregistré avec succès !")
        else:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")

    # Fonction pour afficher la liste des sites avec des mots de passe enregistrés
    def show_passwords(self):
        self.password_list.delete(0, tk.END)

        try:
            with open("passwords.txt", "r") as file:
                lines = file.readlines()
                for line in lines:
                    if line.startswith("Site:"):
                        site = line.split("Site:")[1].split(",")[0].strip()
                        self.password_list.insert(tk.END, site)
        except FileNotFoundError:
            pass

    # Fonction pour déchiffrer le mot de passe enregistré pour le site sélectionné
    def get_password(self,Event):
        self.maitre_password = Toplevel(self.app)
        self.maitre_password.title(".")

        self.master_password_label = tk.Label(self.maitre_password, text="Mot de passe maître:")
        self.master_password_label.pack(padx=5)

        self.master_password_entry = tk.Entry(self.maitre_password, show='*', width=30)
        self.master_password_entry.pack(padx=7)

        self.master_password_entry.focus_set()

        self.ok = tk.Button(self.maitre_password, text=" ok ",command=self.decrypt_pass)
        self.ok.pack(pady=2)

        self.master_password_entry.bind("<Return>", self.decrypt_pass)

    def decrypt_pass(self,Event):

        selected_site = self.password_list.get(self.password_list.curselection())
        master_password = self.master_password_entry.get()


        try:
            with open("passwords.txt", "r") as file:
                lines = file.readlines()
                for line in lines:
                    if line.startswith(f"Site: {selected_site}, Password:"):
                        encrypted_password = line.split("Password:")[1].strip()
                        salt = b'salt'  # Assurez-vous d'utiliser le même sel que lors de l'enregistrement
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            iterations=100000,
                            salt=salt,
                            length=32,
                        )
                        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

                        fernet = Fernet(key)
                        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                        pyperclip.copy(decrypted_password)
                        messagebox.showinfo("copié!", "mot de passe copié dans le presse papier.")
                        self.maitre_password.destroy()

        except FileNotFoundError:
            pass

    # Fonction pour afficher la fenêtre de création d'un nouveau mot de passe
    def create_new_password_window(self):
        self.new_password_window = Toplevel(self.app)
        self.new_password_window.title(".")
        self.new_password_window.geometry(f"{170}x{190}")



        self.master_password_label = tk.Label(self.new_password_window, text="Mot de passe maître:")
        self.master_password_label.pack()

        self.master_password_entry = tk.Entry(self.new_password_window, show='*')
        self.master_password_entry.pack()

        new_site_label = tk.Label(self.new_password_window, text="Site web:")
        new_site_label.pack()

        new_site_entry = tk.Entry(self.new_password_window)
        new_site_entry.pack()

        generate_new_password_button = tk.Button(self.new_password_window, text="Générer un mot de passe", command=self.generate_password)
        generate_new_password_button.pack()

        new_password_label = tk.Label(self.new_password_window, text="Mot de passe:")
        new_password_label.pack()

        self.new_password_entry = tk.Entry(self.new_password_window)
        self.new_password_entry.pack()

        save_new_password_button = tk.Button(self.new_password_window, text="Enregistrer le mot de passe", command=lambda: self.save_new_password(new_site_entry.get(), self.new_password_entry.get()))
        save_new_password_button.pack(pady=4)

    # Fonction pour enregistrer le nouveau mot de passe
    def save_new_password(self, site, password):
        master_password = self.master_password_entry.get()

        if site and password and master_password:
            salt = b'salt'  # Vous devriez générer un sel unique pour chaque mot de passe
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                iterations=100000,
                salt=salt,
                length=32,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

            fernet = Fernet(key)
            encrypted_password = fernet.encrypt(password.encode()).decode()

            with open("passwords.txt", "a") as file:
                file.write(f"Site: {site}, Password: {encrypted_password}\n")

            self.new_password_window.destroy()


            messagebox.showinfo("Success", "Mot de passe enregistré avec succès !")


        else:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
        self.show_passwords()

    def run(self):
        self.app.mainloop()

if __name__ == "__main__":
    manager = PasswordManager()
    manager.run()
