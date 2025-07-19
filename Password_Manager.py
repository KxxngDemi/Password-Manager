from tkinter import *
from tkinter import ttk
import sqlite3
from cryptography.fernet import Fernet
import hashlib
import base64


conn = sqlite3.connect("vault.db")
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
)
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS vault (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    site TEXT,
    site_username TEXT,
    site_password TEXT
)
''')

conn.commit()

# Derive key from master password (using SHA256 and base64)
def generate_key(password):
    hash_obj = hashlib.sha256(password.encode())
    return base64.urlsafe_b64encode(hash_obj.digest())

def encrypt_password(password, key):
    return Fernet(key).encrypt(password.encode()).decode()

def decrypt_password(token, key):
    return Fernet(key).decrypt(token.encode()).decode()



# Function to create a new account
def create_account():
    def save_account():
        username = username_entry.get()
        password = password_entry.get()

        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Check if user already exists
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            status_label.config(text="Username already exists!", fg="red")
        else:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            status_label.config(text="Account created successfully!", fg="green")
            CA_window.after(1500, CA_window.destroy)

    CA_window = Toplevel(main_window)
    CA_window.title("Create Account")
    CA_window.geometry("300x200")
    CA_window.config(background="lightblue")

    Label(CA_window, text="Username:").pack(pady=5)
    username_entry = Entry(CA_window)
    username_entry.pack(pady=5)

    Label(CA_window, text="Password:").pack(pady=5)
    password_entry = Entry(CA_window, show='*')
    password_entry.pack(pady=5)

    status_label = Label(CA_window, text="", bg="lightblue")
    status_label.pack(pady=5)

    Button(CA_window, text="Create", command=save_account).pack(pady=10)
# Function to log in
def login():
    def verify_login():
        username = username_entry.get()
        password = password_entry.get()
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cursor.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (username, password_hash))
        if cursor.fetchone():
            status_label.config(text="Login successful!", fg="green")
            Login_window.after(1500, lambda: [Login_window.destroy(), open_vault(username, password)])
        else:
            status_label.config(text="Invalid credentials!", fg="red")

    Login_window = Toplevel(main_window)
    Login_window.title("Login")
    Login_window.geometry("300x200")
    Login_window.config(background="lightblue")

    Label(Login_window, text="Username:").pack(pady=5)
    username_entry = Entry(Login_window)
    username_entry.pack(pady=5)

    Label(Login_window, text="Password:").pack(pady=5)
    password_entry = Entry(Login_window, show='*')
    password_entry.pack(pady=5)

    status_label = Label(Login_window, text="", bg="lightblue")
    status_label.pack(pady=5)

    Button(Login_window, text="Login", command=verify_login).pack(pady=10)

def open_vault(username, master_password):
    vault = Toplevel(main_window)
    vault.title("Vault")
    vault.geometry("400x300")
    vault.config(background="lightblue")
    
    Label(vault, text=f"Vault for {username}", font=("Arial", 14), bg="lightblue").pack(pady=20)

    Button(vault, text="Add Password", command=lambda: add_password(username, master_password)).pack(pady=10)
    Button(vault, text="View Passwords", command=lambda: view_passwords(username, master_password)).pack(pady=10)
    Button(vault, text="Logout", command=vault.destroy).pack(pady=10)

def add_password(username, master_password):

    def save_password():
        site = site_entry.get()
        site_username = site_username_entry.get()
        site_password = site_password_entry.get()

        key = generate_key(master_password)
        encrypted_password = encrypt_password(site_password, key)

        cursor.execute("INSERT INTO vault (username, site, site_username, site_password) VALUES (?, ?, ?, ?)",
                       (username, site, site_username, encrypted_password))
        conn.commit()
        status_label.config(text="Password added successfully!", fg="green")
        AP_window.after(1500, AP_window.destroy)

    AP_window = Toplevel(main_window)
    AP_window.title("Add Password")
    AP_window.geometry("300x250")
    AP_window.config(background="lightblue")

    Label(AP_window, text="Site:").pack(pady=5)
    site_entry = Entry(AP_window)
    site_entry.pack(pady=5)

    Label(AP_window, text="Username:").pack(pady=5)
    site_username_entry = Entry(AP_window)
    site_username_entry.pack(pady=5)

    Label(AP_window, text="Password:").pack(pady=5)
    site_password_entry = Entry(AP_window, show='*')
    site_password_entry.pack(pady=5)

    status_label = Label(AP_window, text="", bg="lightblue")
    status_label.pack(pady=5)

    Button(AP_window, text="Save", command=save_password).pack(pady=10)
def view_passwords(username, master_password):
    def refresh_tree():
        for row in tree.get_children():
            tree.delete(row)
        cursor.execute("SELECT id, site, site_username, site_password FROM vault WHERE username=?", (username,))
        rows = cursor.fetchall()
        for row_id, site, site_user, enc_pass in rows:
            try:
                dec_pass = decrypt_password(enc_pass, key)
            except:
                dec_pass = "DECRYPTION FAILED"
            tree.insert("", "end", iid=row_id, values=(site, site_user, dec_pass))

    def copy_to_clipboard(event):
        selected_item = tree.selection()
        if selected_item:
            item = tree.item(selected_item)
            password = item["values"][2]
            view_window.clipboard_clear()
            view_window.clipboard_append(password)
            status_label.config(text="Password copied to clipboard!", fg="green")

    def delete_selected():
        selected_item = tree.selection()
        if selected_item:
            item_id = selected_item[0]
            cursor.execute("DELETE FROM vault WHERE id=?", (item_id,))
            conn.commit()
            refresh_tree()
            status_label.config(text="Entry deleted.", fg="red")

    def edit_selected(event):
        selected_item = tree.selection()
        if selected_item:
            item_id = selected_item[0]
            values = tree.item(item_id, "values")

            def save_edit():
                new_site = site_entry.get()
                new_user = user_entry.get()
                new_pass = pass_entry.get()
                enc_pass = encrypt_password(new_pass, key)
                cursor.execute("UPDATE vault SET site=?, site_username=?, site_password=? WHERE id=?",
                               (new_site, new_user, enc_pass, item_id))
                conn.commit()
                edit_win.destroy()
                refresh_tree()
                status_label.config(text="Entry updated.", fg="green")

            edit_win = Toplevel(view_window)
            edit_win.title("Edit Credential")
            edit_win.geometry("300x250")
            edit_win.config(bg="lightblue")

            Label(edit_win, text="Site:").pack(pady=5)
            site_entry = Entry(edit_win)
            site_entry.insert(0, values[0])
            site_entry.pack()

            Label(edit_win, text="Site Username:").pack(pady=5)
            user_entry = Entry(edit_win)
            user_entry.insert(0, values[1])
            user_entry.pack()

            Label(edit_win, text="Site Password:").pack(pady=5)
            pass_entry = Entry(edit_win)
            pass_entry.insert(0, values[2])
            pass_entry.pack()

            Button(edit_win, text="Save Changes", command=save_edit).pack(pady=10)

    # Window Setup
    view_window = Toplevel(main_window)
    view_window.title("Stored Passwords")
    view_window.geometry("650x350")
    view_window.config(background="lightblue")

    key = generate_key(master_password)

    # Treeview + Scrollbar
    frame = Frame(view_window)
    frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

    tree = ttk.Treeview(frame, columns=("Site", "Username", "Password"), show='headings', selectmode='browse')
    tree.heading("Site", text="Site")
    tree.heading("Username", text="Site Username")
    tree.heading("Password", text="Site Password")
    tree.column("Site", width=200)
    tree.column("Username", width=180)
    tree.column("Password", width=200)

    vsb = Scrollbar(frame, orient=VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.pack(side=RIGHT, fill=Y)
    tree.pack(fill=BOTH, expand=True)

    # Copy to clipboard on click
    tree.bind("<ButtonRelease-1>", copy_to_clipboard)

    # Edit on double-click
    tree.bind("<Double-Button-1>", edit_selected)

    # Delete Button
    Button(view_window, text="Delete Selected", command=delete_selected, bg="red", fg="white").pack(pady=5)

    status_label = Label(view_window, text="", bg="lightblue")
    status_label.pack(pady=5)

    refresh_tree()
    
# Main page of the application
main_window = Tk()
main_window.title("Password Manager")
main_window.geometry("400x300")
main_window.config(background="lightblue")

Label(main_window, text="Password Manager", font=("Arial", 16), bg="lightblue").pack(pady=20)
Button(main_window, text="Create Account", command=create_account).pack(pady=10)
Button(main_window, text="Login", command=login).pack(pady=10)
Button(main_window, text="Exit", command=main_window.quit).pack(pady=10)


main_window.mainloop()

