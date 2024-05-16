import tkinter as tk
from tkinter import ttk, messagebox
import traceback
import datetime
import gpt_module
import aes_module
import des_module
import triple_des_module
import blowfish_module
import os

class CryptoApp:
    def __init__(self, master):
        self.master = master
        master.title("CryptoGPT - Your secure Chat Companion")

        self.style = ttk.Style()
        self.style.configure('Submit.TButton', foreground='red', background='#4CAF50')
        self.style.configure('Mode.TMenubutton', foreground='black', background='#2196F3')

        self.create_widgets()

    def create_widgets(self):
        input_frame = ttk.Frame(self.master)
        input_frame.pack(pady=10)

        self.plaintext_label = ttk.Label(input_frame, text="Enter Plaintext/Ciphertext:")
        self.plaintext_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

        self.plaintext_entry = ttk.Entry(input_frame, width=40)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=5)

        self.key_label = ttk.Label(input_frame, text="Enter Key:")
        self.key_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")

        self.key_entry = ttk.Entry(input_frame, width=40, show="*")
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)

        self.mode_label = ttk.Label(input_frame, text="Select Mode:")
        self.mode_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")

        self.mode_var = tk.StringVar(self.master)  
        self.mode_var.set("Encrypt")
        self.mode_option_menu = ttk.OptionMenu(input_frame, self.mode_var, "Encrypt", "Decrypt", command=self.update_mode_options, style='Mode.TMenubutton')
        self.mode_option_menu.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        self.algorithm_label = ttk.Label(input_frame, text="Select Algorithm:")
        self.algorithm_label.grid(row=3, column=0, padx=5, pady=5, sticky="e")

        self.algorithm_var = tk.StringVar(self.master)  
        self.algorithm_var.set("AES")
        self.algorithm_option_menu = ttk.OptionMenu(input_frame, self.algorithm_var, "AES", "DES", "3DES", "Blowfish", style='Mode.TMenubutton')
        self.algorithm_option_menu.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        self.output_label = ttk.Label(input_frame, text="Output:")
        self.output_label.grid(row=4, column=0, padx=5, pady=5, sticky="e")

        self.output_text = tk.Text(input_frame, width=40, height=5)
        self.output_text.grid(row=4, column=1, padx=5, pady=5)

        self.submit_button = ttk.Button(input_frame, text="Submit", command=self.submit, style='Submit.TButton')
        self.submit_button.grid(row=5, column=0, columnspan=2, pady=10)

    def update_mode_options(self, mode):
        # Update options based on selected mode
        if mode == "Encrypt":
            self.algorithm_option_menu['menu'].delete(0, "end")
            for algorithm in ["AES", "DES", "3DES", "Blowfish"]:
                self.algorithm_option_menu['menu'].add_command(label=algorithm, command=lambda alg=algorithm: self.algorithm_var.set(alg))
        elif mode == "Decrypt":
            self.algorithm_option_menu['menu'].delete(0, "end")
            self.algorithm_option_menu['menu'].add_command(label="AES", command=lambda: self.algorithm_var.set("AES"))
        else:
            messagebox.showerror("Error", "Invalid mode selected.")

    def submit(self):
        plaintext = self.plaintext_entry.get()
        key = self.key_entry.get()
        mode = self.mode_var.get()
        algorithm = self.algorithm_var.get()
    
    # Initialize ciphertext variable
        ciphertext = ""
        decrypted_text = ""

        suggestion = ""  # Initialize suggestion variable

        try:
            if algorithm == "AES":
                key = key.ljust(32, '\0')[:32]
                if mode == "Encrypt":
                    suggestion = gpt_module.gpt_model.get_encryption_suggestion(plaintext, key)
                else:
                    suggestion = gpt_module.gpt_model.get_decryption_suggestion(plaintext, key)
                if suggestion:
                    messagebox.showinfo("GPT Suggestion", suggestion)

                if mode == "Encrypt":
                    ciphertext = aes_module.encrypt(plaintext, key)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"Ciphertext: {ciphertext}")
                else:
                    decrypted_text = aes_module.decrypt(plaintext, key)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"Decrypted Text: {decrypted_text}")
            elif algorithm == "DES":
                if mode == "Encrypt":
                    ciphertext = des_module.encrypt(plaintext, key)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"Ciphertext: {ciphertext}")
                else:
                    decrypted_text = des_module.decrypt(plaintext, key)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"Decrypted Text: {decrypted_text}")
            elif algorithm == "3DES":
                if mode == "Encrypt":
                    ciphertext = triple_des_module.encrypt(plaintext, key)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"Ciphertext: {ciphertext}")
                else:
                    decrypted_text = triple_des_module.decrypt(plaintext, key)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"Decrypted Text: {decrypted_text}")
            elif algorithm == "Blowfish":
                if mode == "Encrypt":
                    ciphertext = blowfish_module.encrypt(plaintext, key)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"Ciphertext: {ciphertext}")
                else:
                    decrypted_text = blowfish_module.decrypt(plaintext, key)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"Decrypted Text: {decrypted_text}")

        # Write input and output to a text file
            self.write_to_file(plaintext, key, mode, algorithm, ciphertext, decrypted_text)
        except Exception as ex:
            traceback.print_exc()


    def write_to_file(self, plaintext, key, mode, algorithm, ciphertext, decrypted_text):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file = "crypto_log.txt"
        
        # Check if the log file exists, create it if it doesn't
        if not os.path.exists(log_file):
            with open(log_file, "w") as file:
                file.write("Crypto Log\n\n")
        
        # Append data to the log file
        with open(log_file, "a") as file:
            file.write(f"Timestamp: {timestamp}\n")
            file.write(f"Plaintext: {plaintext}\n")
            file.write(f"Key: {key}\n")
            file.write(f"Mode: {mode}\n")
            file.write(f"Algorithm: {algorithm}\n")
            file.write(f"Ciphertext: {ciphertext}\n")
            file.write(f"Decrypted Text: {decrypted_text}\n")
            file.write("\n")


def main():
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
