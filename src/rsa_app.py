"""
RSA Encryption/Decryption System with GUI
Developed as part of academic project for Cryptography course

This implementation is for educational purposes and demonstrates the RSA algorithm
with a graphical user interface. It supports key generation, encryption, and decryption
of messages with Unicode support.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import base64
import json
from sympy import randprime, mod_inverse
import os

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption/Decryption System")
        self.root.geometry("800x700")  # Increased height for status bar
        
        # Initialize RSA parameters
        self.p = None
        self.q = None
        self.n = None
        self.phi = None
        self.e = None
        self.d = None
        
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(expand=True, fill='both', padx=10, pady=5)
        
        self.setup_gui()
        self.setup_status_bar()
        
        # Set initial status
        self.update_status("Ready")
    
    def setup_status_bar(self):
        """Create a status bar at the bottom of the window"""
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            padding=(5, 2)
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message):
        """Update status bar message"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def setup_gui(self):
        """Set up the graphical user interface"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.main_container)
        notebook.pack(expand=True, fill='both')
        
        # === Key Generation Tab ===
        key_frame = ttk.Frame(notebook)
        notebook.add(key_frame, text="Key Generation")
        
        # Key size selection
        key_size_frame = ttk.LabelFrame(key_frame, text="Key Configuration", padding=10)
        key_size_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(key_size_frame, text="Select Key Size (bits):").pack(side=tk.LEFT, padx=5)
        self.key_size_var = tk.StringVar(value="256")
        key_sizes = ttk.Combobox(key_size_frame, textvariable=self.key_size_var, width=10)
        key_sizes['values'] = ("256", "512", "1024")
        key_sizes.pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        btn_frame = ttk.Frame(key_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(btn_frame, text="Generate Keys", command=self.generate_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Keys", command=self.save_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Load Keys", command=self.load_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", command=lambda: self.key_output.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        
        # Output area
        self.key_output = scrolledtext.ScrolledText(key_frame, width=70, height=20)
        self.key_output.pack(padx=5, pady=5, expand=True, fill='both')
        
        # === Encryption Tab ===
        encrypt_frame = ttk.Frame(notebook)
        notebook.add(encrypt_frame, text="Encryption")
        
        # Input frame
        enc_input_frame = ttk.LabelFrame(encrypt_frame, text="Message Input", padding=10)
        enc_input_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(enc_input_frame, text="Enter message:").pack(anchor=tk.W)
        self.message_input = ttk.Entry(enc_input_frame, width=70)
        self.message_input.pack(fill='x', pady=5)
        
        # Buttons
        enc_btn_frame = ttk.Frame(encrypt_frame)
        enc_btn_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(enc_btn_frame, text="Encrypt", command=self.encrypt_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(enc_btn_frame, text="Clear", 
                  command=lambda: [self.message_input.delete(0, tk.END), 
                                 self.encrypt_output.delete(1.0, tk.END)]).pack(side=tk.LEFT, padx=5)
        
        # Output
        enc_output_frame = ttk.LabelFrame(encrypt_frame, text="Encryption Output", padding=10)
        enc_output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.encrypt_output = scrolledtext.ScrolledText(enc_output_frame, width=70, height=15)
        self.encrypt_output.pack(expand=True, fill='both')
        
        # === Decryption Tab ===
        decrypt_frame = ttk.Frame(notebook)
        notebook.add(decrypt_frame, text="Decryption")
        
        # Input frame
        dec_input_frame = ttk.LabelFrame(decrypt_frame, text="Ciphertext Input", padding=10)
        dec_input_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(dec_input_frame, text="Enter ciphertext:").pack(anchor=tk.W)
        self.cipher_input = ttk.Entry(dec_input_frame, width=70)
        self.cipher_input.pack(fill='x', pady=5)
        
        # Buttons
        dec_btn_frame = ttk.Frame(decrypt_frame)
        dec_btn_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(dec_btn_frame, text="Decrypt", command=self.decrypt_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(dec_btn_frame, text="Clear",
                  command=lambda: [self.cipher_input.delete(0, tk.END),
                                 self.decrypt_output.delete(1.0, tk.END)]).pack(side=tk.LEFT, padx=5)
        
        # Output
        dec_output_frame = ttk.LabelFrame(decrypt_frame, text="Decryption Output", padding=10)
        dec_output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.decrypt_output = scrolledtext.ScrolledText(dec_output_frame, width=70, height=15)
        self.decrypt_output.pack(expand=True, fill='both')

    def save_keys(self):
        """Save the current key pair to a JSON file"""
        if not all([self.n, self.e, self.d]):
            messagebox.showerror("Error", "No keys to save. Generate keys first!")
            return
            
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Save RSA Keys"
            )
            
            if not file_path:
                return
                
            keys = {
                "public_key": {
                    "n": str(self.n),
                    "e": str(self.e)
                },
                "private_key": {
                    "n": str(self.n),
                    "d": str(self.d)
                }
            }
            
            with open(file_path, 'w') as f:
                json.dump(keys, f, indent=4)
                
            self.update_status(f"Keys saved to {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save keys: {str(e)}")

    def load_keys(self):
        """Load RSA keys from a JSON file"""
        try:
            file_path = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Load RSA Keys"
            )
            
            if not file_path:
                return
                
            with open(file_path, 'r') as f:
                keys = json.load(f)
                
            self.n = int(keys["public_key"]["n"])
            self.e = int(keys["public_key"]["e"])
            self.d = int(keys["private_key"]["d"])
            
            # Display loaded keys
            self.key_output.delete(1.0, tk.END)
            self.key_output.insert(tk.END, "Loaded Keys:\n\n")
            self.key_output.insert(tk.END, f"Public Key (e, n):\n")
            self.key_output.insert(tk.END, f"e: {self.e}\n")
            self.key_output.insert(tk.END, f"n: {self.n}\n\n")
            self.key_output.insert(tk.END, f"Private Key (d, n):\n")
            self.key_output.insert(tk.END, f"d: {self.d}\n")
            self.key_output.insert(tk.END, f"n: {self.n}\n")
            
            self.update_status(f"Keys loaded from {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys: {str(e)}")

    def generate_keys(self):
        """Generate RSA public and private keys"""
        try:
            self.update_status("Generating keys...")
            
            # Get selected key size and split between p and q
            key_bits = int(self.key_size_var.get()) // 2
            self.key_output.delete(1.0, tk.END)
            self.key_output.insert(tk.END, "Generating keys...\n\n")
            
            # Generate prime numbers
            self.p = randprime(2**(key_bits-1), 2**key_bits)
            self.q = randprime(2**(key_bits-1), 2**key_bits)
            
            while self.p == self.q:
                self.q = randprime(2**(key_bits-1), 2**key_bits)
            
            self.n = self.p * self.q
            self.phi = (self.p - 1) * (self.q - 1)
            self.e = 65537
            self.d = mod_inverse(self.e, self.phi)
            
            # Display results
            self.key_output.insert(tk.END, f"Generated prime p: {self.p}\n")
            self.key_output.insert(tk.END, f"Generated prime q: {self.q}\n\n")
            self.key_output.insert(tk.END, f"Public Key (e, n):\n")
            self.key_output.insert(tk.END, f"e: {self.e}\n")
            self.key_output.insert(tk.END, f"n: {self.n}\n\n")
            self.key_output.insert(tk.END, f"Private Key (d, n):\n")
            self.key_output.insert(tk.END, f"d: {self.d}\n")
            self.key_output.insert(tk.END, f"n: {self.n}\n")
            
            self.update_status("Keys generated successfully")
            
        except Exception as e:
            self.update_status("Key generation failed")
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")

    def check_message_size(self, message_int):
        """Check if the message size is valid for the current key"""
        max_bytes = (self.n.bit_length() - 1) // 8
        message_bytes = (message_int.bit_length() + 7) // 8
        return message_bytes <= max_bytes

    def encrypt_message(self):
        """Encrypt a message using the public key"""
        try:
            if not all([self.e, self.n]):
                raise ValueError("Please generate or load keys first!")
            
            message = self.message_input.get()
            if not message:
                raise ValueError("Please enter a message!")
            
            self.update_status("Encrypting message...")
            
            # Convert message to integer
            message_bytes = message.encode('utf-8')
            m = int.from_bytes(message_bytes, 'big')
            
            # Check message size
            if not self.check_message_size(m):
                raise ValueError(
                    f"Message too long for current key size ({self.n.bit_length()} bits).\n"
                    f"Please use larger keys or a shorter message."
                )
            
            # Encrypt
            c = pow(m, self.e, self.n)
            cipher_text = base64.b64encode(str(c).encode()).decode()
            
            # Display results
            self.encrypt_output.delete(1.0, tk.END)
            self.encrypt_output.insert(tk.END, f"Original message: {message}\n")
            self.encrypt_output.insert(tk.END, f"Encrypted (base64): {cipher_text}\n")
            
            # Copy to decryption tab
            self.cipher_input.delete(0, tk.END)
            self.cipher_input.insert(0, cipher_text)
            
            self.update_status("Message encrypted successfully")
            
        except Exception as e:
            self.update_status("Encryption failed")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_message(self):
        """Decrypt a message using the private key"""
        try:
            if not all([self.d, self.n]):
                raise ValueError("Please generate or load keys first!")
            
            cipher_text = self.cipher_input.get()
            if not cipher_text:
                raise ValueError("Please enter ciphertext!")
            
            self.update_status("Decrypting message...")
            
            # Decode base64 and convert to integer
            c = int(base64.b64decode(cipher_text).decode())
            
            # Decrypt
            m = pow(c, self.d, self.n)
            
            try:
                decrypted_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                decrypted_message = decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Decryption failed. The message might be corrupted.")
            
            # Display results
            self.decrypt_output.delete(1.0, tk.END)
            self.decrypt_output.insert(tk.END, f"Decrypted message: {decrypted_message}\n")
            
            self.update_status("Message decrypted successfully")
            
        except Exception as e:
            self.update_status("Decryption failed")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
