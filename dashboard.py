import customtkinter as ctk
import tkinter as tk
from tkinter import simpledialog, messagebox
import pyperclip
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from auth import register, login
from encryptor import derive_key, encrypt_password, decrypt_password
from db import update_vault

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        # Set window to full screen
        self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}")
        self.resizable(True, True)

        self.user = None
        self.key = None

        self.sidebar = Sidebar(self, self.switch_mode)
        self.sidebar.pack(side="left", fill="y")

        self.content = ContentArea(self)
        self.content.pack(side="right", expand=True, fill="both")

        # Keyboard shortcut for quitting
        self.bind('<Control-q>', lambda event: self.sidebar.exit_app())

    def switch_mode(self, mode):
        self.content.show_mode(mode, self.user, self.key)

class Sidebar(ctk.CTkFrame):
    def __init__(self, master, switch_callback):
        super().__init__(master, width=180)
        self.switch_callback = switch_callback

        self.dashboard_btn = ctk.CTkButton(self, text="Dashboard", command=lambda: switch_callback("dashboard"))
        self.dashboard_btn.pack(pady=10, padx=10)

        self.generate_btn = ctk.CTkButton(self, text="Generate", command=lambda: switch_callback("generator"))
        self.generate_btn.pack(pady=10, padx=10)

        self.stats_btn = ctk.CTkButton(self, text="Usage Stats", command=lambda: switch_callback("stats"))
        self.stats_btn.pack(pady=10, padx=10)

        self.theme_toggle = ctk.CTkSwitch(self, text="Dark Mode", command=self.toggle_theme)
        self.theme_toggle.pack(pady=20, padx=10)

        self.exit_btn = ctk.CTkButton(self, text="Exit", fg_color="red", command=self.exit_app)
        self.exit_btn.pack(pady=20, padx=10)

        self.minimize_btn = ctk.CTkButton(self, text="Minimize", command=self.master.iconify)
        self.minimize_btn.pack(pady=10, padx=10)

    def toggle_theme(self):
        if self.theme_toggle.get():
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")

    def exit_app(self):
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.master.quit()

class ContentArea(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.root = master
        self.login_screen()

    def login_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.user_entry = ctk.CTkEntry(self, placeholder_text="Username")
        self.user_entry.pack(pady=10)

        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        self.pass_entry.pack(pady=10)

        self.login_btn = ctk.CTkButton(self, text="Login", command=self.login_user)
        self.login_btn.pack(pady=5)

        self.reg_btn = ctk.CTkButton(self, text="Register", command=self.register_user)
        self.reg_btn.pack(pady=5)

    def login_user(self):
        uname = self.user_entry.get()
        passwd = self.pass_entry.get()
        success, result = login(uname, passwd)
        if success:
            self.root.user = result
            self.root.key = derive_key(passwd)
            self.show_dashboard(self.root.user, self.root.key)
        else:
            messagebox.showerror("Error", result)

    def register_user(self):
        uname = self.user_entry.get()
        passwd = self.pass_entry.get()
        success, result = register(uname, passwd)
        messagebox.showinfo("Register", result)

    def show_mode(self, mode, user, key):
        if mode == "dashboard":
            self.show_dashboard(user, key)
        elif mode == "generator":
            self.show_generator()
        elif mode == "stats":
            self.show_stats(user)

    def show_dashboard(self, user, key):
        for widget in self.winfo_children():
            widget.destroy()

        vault = user.get("vault", [])

        def add_entry():
            site = simpledialog.askstring("Add", "Site")
            login_ = simpledialog.askstring("Add", "Login")
            pwd = simpledialog.askstring("Add", "Password")
            encrypted_pwd = encrypt_password(pwd, key)
            vault.append({"site": site, "login": login_, "password": encrypted_pwd})
            update_vault(user["username"], vault)
            user["vault"] = vault
            self.show_dashboard(user, key)

        def delete_entry(index):
            del vault[index]
            update_vault(user["username"], vault)
            user["vault"] = vault
            self.show_dashboard(user, key)

        def toggle_password(index, label):
            entry = vault[index]
            if label.cget("text").startswith("*"):
                label.configure(text=decrypt_password(entry["password"], key))
            else:
                label.configure(text="*" * 8)

        def logout_user():
            self.root.user = None
            self.root.key = None
            self.login_screen()

        ctk.CTkLabel(self, text=f"Welcome, {user['username']}", font=("Arial", 18)).pack(pady=10)

        for i, entry in enumerate(vault):
            row = ctk.CTkFrame(self)
            row.pack(pady=5, padx=10, fill="x")

            ctk.CTkLabel(row, text=entry["site"], width=100).pack(side="left")
            ctk.CTkLabel(row, text=entry["login"], width=150).pack(side="left")
            pwd_lbl = ctk.CTkLabel(row, text="*" * 8)
            pwd_lbl.pack(side="left", padx=5)

            ctk.CTkButton(row, text="Show", command=lambda i=i, lbl=pwd_lbl: toggle_password(i, lbl)).pack(side="left")
            ctk.CTkButton(row, text="Delete", command=lambda i=i: delete_entry(i)).pack(side="left", padx=5)

        ctk.CTkButton(self, text="Add New", command=add_entry).pack(pady=10)
        ctk.CTkButton(self, text="Logout", fg_color="red", command=logout_user).pack(pady=5)

    def show_generator(self):
        for widget in self.winfo_children():
            widget.destroy()

        import random
        import string

        def generate_password():
            chars = string.ascii_letters + string.digits + string.punctuation
            pwd = ''.join(random.choices(chars, k=12))
            result_entry.delete(0, tk.END)
            result_entry.insert(0, pwd)
            pyperclip.copy(pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

        ctk.CTkLabel(self, text="Password Generator", font=("Arial", 18)).pack(pady=20)
        result_entry = ctk.CTkEntry(self, width=300)
        result_entry.pack(pady=10)

        ctk.CTkButton(self, text="Generate", command=generate_password).pack(pady=10)

    def show_stats(self, user):
        for widget in self.winfo_children():
            widget.destroy()

        data = {}
        for entry in user.get("vault", []):
            site = entry["site"]
            data[site] = data.get(site, 0) + 1

        if not data:
            ctk.CTkLabel(self, text="No data to display").pack()
            return

        fig, ax = plt.subplots(figsize=(5, 4))
        ax.bar(data.keys(), data.values())
        ax.set_title("Password Usage by Site")
        ax.set_ylabel("Entries")

        canvas = FigureCanvasTkAgg(fig, master=self)
        canvas.draw()
        canvas.get_tk_widget().pack()


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
