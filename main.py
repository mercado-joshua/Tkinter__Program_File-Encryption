#===========================
# Imports
#===========================
import tkinter as tk
from tkinter import ttk, colorchooser as cc, Menu, Spinbox as sb, scrolledtext as st, messagebox as mb, filedialog as fd, simpledialog as sd

import os
from cryptography.fernet import Fernet

#===========================
# Main App
#===========================
class App(tk.Tk):
    """Main Application."""
    #------------------------------------------
    # Initializer
    #------------------------------------------
    def __init__(self):
        super().__init__()
        self.init_config()
        self.init_vars()
        self.init_widgets()

    #------------------------------------------
    # Instance Variables
    #------------------------------------------
    def init_vars(self):
        with open('key.txt', 'rb') as file_key:
            self.key = file_key.read()

    #-------------------------------------------
    # Window Settings
    #-------------------------------------------
    def init_config(self):
        self.resizable(False, False)
        self.title('File Encryption Version 1.0')
        self.iconbitmap('python.ico')
        self.style = ttk.Style(self)
        self.style.theme_use('clam')

    #-------------------------------------------
    # Widgets / Components
    #-------------------------------------------
    def init_widgets(self):
        frame = ttk.Frame(self)
        frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(frame)
        notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        tab_1 = ttk.Frame(notebook)
        notebook.add(tab_1, text='Key')
        tab_2 = ttk.Frame(notebook)
        notebook.add(tab_2, text='Encrypt')
        tab_3 = ttk.Frame(notebook)
        notebook.add(tab_3, text='Decrypt')
        notebook.select(0)

        # ------------------------------------------
        label = ttk.Label(tab_1, text='Current Key')
        label.pack(side=tk.TOP, anchor=tk.NW, fill=tk.X, padx=10, pady=(10, 0))

        self.keyname = tk.StringVar()
        self.keyname.set(self.key)
        self.entry = ttk.Entry(tab_1, width=80, textvariable=self.keyname, state=tk.DISABLED)
        self.entry.pack(side=tk.TOP, anchor=tk.NW, fill=tk.X, padx=10, ipady=5)

        self.button = ttk.Button(tab_1, text='Generate New Key', command=self.create_key)
        self.button.pack(side=tk.RIGHT, anchor=tk.W, padx=(0, 10), pady=10)

        # ------------------------------------------
        fieldset = ttk.LabelFrame(tab_2, text='File to Encrypt')
        fieldset.pack(side=tk.TOP, expand=True, padx=10, pady=(10, 0), fill=tk.BOTH)

        self.button = ttk.Button(fieldset, text='Browse', command=self.get_file)
        self.button.pack(side=tk.LEFT, anchor=tk.NW)

        self.filename = tk.StringVar()
        self.entry1 = ttk.Entry(fieldset, width=80, textvariable=self.filename, state=tk.DISABLED)
        self.entry1.pack(side=tk.LEFT, anchor=tk.NW, fill=tk.X, ipady=5)

        self.button = ttk.Button(tab_2, text='Encrypt', command=self.file_to_encrypt)
        self.button.pack(side=tk.RIGHT, anchor=tk.W, padx=(0, 10), pady=10)

        # ------------------------------------------
        fieldset = ttk.LabelFrame(tab_3, text='File to Decrypt')
        fieldset.pack(side=tk.TOP, expand=True, padx=10, pady=(10, 0), fill=tk.BOTH)

        self.button = ttk.Button(fieldset, text='Browse', command=self.get_encryted_file)
        self.button.pack(side=tk.LEFT, anchor=tk.NW)

        self.encrypted_filename = tk.StringVar()
        self.entry2 = ttk.Entry(fieldset, width=80, textvariable=self.encrypted_filename)
        self.entry2.pack(side=tk.LEFT, anchor=tk.NW, fill=tk.X, ipady=5)

        self.button = ttk.Button(tab_3, text='Decrypt', command=self.file_to_decrypt)
        self.button.pack(side=tk.RIGHT, anchor=tk.W, padx=(0, 10), pady=10)

    # ------------------------------------------
    def create_key(self):
        self.entry.config(state=tk.NORMAL)
        key = Fernet.generate_key()
        with open('key.txt', 'wb') as file_key:
            file_key.write(key)
        self.keyname.set(key)
        self.entry.config(state=tk.DISABLED)

    def get_file(self):
        self.entry1.config(state=tk.NORMAL)
        file = fd.askopenfile(mode='r')
        self.name = file.name
        self.filename.set(self.name)
        self.entry1.config(state=tk.DISABLED)

    def file_to_encrypt(self):
        name = os.path.basename(self.filename.get())
        new_filename = f'encrypted.{name}'

        with open(self.filename.get(), 'rb') as file:
            data = file.read()

        fernet = Fernet(self.key)
        encrypted = fernet.encrypt(data)

        with open(new_filename, 'wb') as file:
            file.write(encrypted)

    def get_encryted_file(self):
        self.entry2.config(state=tk.NORMAL)
        file = fd.askopenfile(mode='r')
        self.name = file.name
        self.encrypted_filename.set(self.name)
        self.entry2.config(state=tk.DISABLED)

    def file_to_decrypt(self):
        name = os.path.basename(self.encrypted_filename.get())
        new_filename = f'decrypted.{name}'

        with open(self.encrypted_filename.get(), 'rb') as file:
            data = file.read()

        fernet = Fernet(self.key)
        decrypted = fernet.decrypt(data)

        with open(new_filename, 'wb') as file:
            file.write(decrypted)

#===========================
# Start GUI
#===========================
def main():
    app = App()
    app.mainloop()

if __name__ == '__main__':
    main()