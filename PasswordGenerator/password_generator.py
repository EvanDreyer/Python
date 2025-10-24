import random
import random
from tkinter import messagebox
from tkinter import *

# Character set to generate passwords from
character_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~"

# Initialize Tkinter window
app_window = Tk()
app_window.geometry("350x250")
app_window.title("Password Generator")

# --- Functions ---

def generate_password():
    try:
        length = int(length_entry.get())
    except ValueError:
        messagebox.showerror("Input Error", "Please enter a valid number for length")
        return

    if length <= 0:
        messagebox.showerror("Input Error", "Password length must be greater than 0")
        return

    # Generate password
    password_list = random.choices(character_string, k=length)
    password = ''.join(password_list)

    # Display in GUI
    password_var.set("Created Password: " + password)

    # Store password in file
    try:
        with open("passwords.txt", "a") as f:
            f.write(password + "\n")
    except Exception as e:
        messagebox.showerror("File Error", f"Failed to store password: {e}")

def view_saved_passwords():
    try:
        with open("passwords.txt", "r") as f:
            passwords = f.read()
    except FileNotFoundError:
        passwords = "No passwords saved yet."

    # Create a new window to show passwords
    view_window = Toplevel(app_window)
    view_window.title("Saved Passwords")
    view_window.geometry("350x250")

    text_box = Text(view_window, wrap=WORD)
    text_box.pack(expand=True, fill=BOTH, padx=10, pady=10)
    text_box.insert(END, passwords)
    text_box.config(state=DISABLED)  # Make it read-only

# --- Widgets ---

# Title label
title_label = Label(app_window, text="Password Generator", font=('Sans-serif', 12))
title_label.pack(pady=5)

# Length input
length_label = Label(app_window, text="Enter length of password: ")
length_label.place(x=20, y=30)
length_entry = Entry(app_window, width=5)
length_entry.place(x=190, y=30)

# Generate button
password_button = Button(app_window, text="Generate Password", command=generate_password)
password_button.place(x=100, y=70)

# Read-only Entry for showing generated password
password_var = StringVar()
password_label = Entry(app_window, bd=0, bg="gray85", textvariable=password_var, state="readonly")
password_label.place(x=10, y=120, height=50, width=320)

# View passwords button
view_button = Button(app_window, text="View Saved Passwords", command=view_saved_passwords)
view_button.place(x=100, y=180)

# Run the Tkinter event loop
app_window.mainloop()
