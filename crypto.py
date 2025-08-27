# Digital Signature and Verification Tool using RSA, ECC, and ECDH with GUI (Improved UI)
#pip install pycryptodome ecdsa
import hashlib
import random
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from Crypto.Util import number
from ecdsa import SigningKey, VerifyingKey, NIST256p
from ecdsa.ellipticcurve import Point

# ---------------------- RSA Functions ----------------------

def generate_rsa_keys(bits=1024):
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return {'public': (e, n), 'private': (d, n)}

def hash_message(message):
    hash_bytes = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(hash_bytes, byteorder='big')

def rsa_sign_message(message, private_key, use_hash=True):
    d, n = private_key
    m = hash_message(message) if use_hash else int(message)
    signature = pow(m, d, n)
    return signature

def rsa_verify_signature(message, signature, public_key, use_hash=True):
    e, n = public_key
    m = hash_message(message) if use_hash else int(message)
    recovered = pow(signature, e, n)
    return m == recovered

# ---------------------- ECC Functions ----------------------

def generate_ecc_keys():
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.get_verifying_key()
    return {'private': sk, 'public': vk}

def ecc_sign_message(message, private_key):
    return private_key.sign(message.encode())

def ecc_verify_signature(message, signature, public_key):
    try:
        return public_key.verify(signature, message.encode())
    except:
        return False

# ---------------------- ECDH Functions ----------------------

def generate_ecdh_keypair():
    """Generate ECDH key pair"""
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.get_verifying_key()
    return {'private': private_key, 'public': public_key}

def ecdh_compute_shared_secret(private_key, public_key):
    """Compute shared secret using ECDH"""
    try:
        # Get the point from the public key
        public_point = public_key.pubkey.point
        
        # Get the private key scalar
        private_scalar = private_key.privkey.secret_multiplier
        
        # Compute shared point: private_key * public_key_point
        shared_point = private_scalar * public_point
        
        # Convert shared point to bytes (using x-coordinate)
        shared_secret = shared_point.x().to_bytes(32, byteorder='big')
        
        return shared_secret
    except Exception as e:
        return None

def derive_key_from_shared_secret(shared_secret, info=b''):
    """Derive a key from shared secret using HKDF-like approach"""
    if shared_secret is None:
        return None
    
    # Simple key derivation using SHA256
    combined = shared_secret + info
    derived_key = hashlib.sha256(combined).digest()
    return derived_key

# ---------------------- GUI State ----------------------

rsa_keys = generate_rsa_keys(bits=512)
rsa_public_key = rsa_keys['public']
rsa_private_key = rsa_keys['private']

ecc_keys = generate_ecc_keys()
ecc_private_key = ecc_keys['private']
ecc_public_key = ecc_keys['public']

# ECDH keys for Alice and Bob
alice_ecdh_keys = generate_ecdh_keypair()
bob_ecdh_keys = generate_ecdh_keypair()

rsa_last_signature = None
ecc_last_signature = None
shared_secret_alice = None
shared_secret_bob = None

# ---------------------- GUI Functions ----------------------

def generate_keys_gui():
    global rsa_keys, rsa_public_key, rsa_private_key
    global ecc_keys, ecc_private_key, ecc_public_key
    global alice_ecdh_keys, bob_ecdh_keys
    
    rsa_keys = generate_rsa_keys(bits=512)
    rsa_public_key = rsa_keys['public']
    rsa_private_key = rsa_keys['private']
    
    ecc_keys = generate_ecc_keys()
    ecc_private_key = ecc_keys['private']
    ecc_public_key = ecc_keys['public']
    
    alice_ecdh_keys = generate_ecdh_keypair()
    bob_ecdh_keys = generate_ecdh_keypair()
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "=== Generated Keys ===\n")
    output_text.insert(tk.END, f"RSA Public Key: {rsa_public_key}\n")
    output_text.insert(tk.END, f"RSA Private Key: {rsa_private_key}\n")
    output_text.insert(tk.END, f"ECC Public Key: {ecc_public_key.to_string().hex()}\n")
    output_text.insert(tk.END, f"ECC Private Key: {ecc_private_key.to_string().hex()}\n")
    output_text.insert(tk.END, f"\n=== ECDH Keys ===\n")
    output_text.insert(tk.END, f"Alice ECDH Public Key: {alice_ecdh_keys['public'].to_string().hex()}\n")
    output_text.insert(tk.END, f"Bob ECDH Public Key: {bob_ecdh_keys['public'].to_string().hex()}\n")

def rsa_sign_gui():
    global rsa_last_signature
    message = input_text.get("1.0", tk.END).strip()
    if not message:
        messagebox.showwarning("Input Required", "Please enter a message.")
        return
    rsa_last_signature = rsa_sign_message(message, rsa_private_key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "=== RSA Signing ===\n")
    output_text.insert(tk.END, f"Message Hash: {hash_message(message)}\n")
    output_text.insert(tk.END, f"RSA Signature: {rsa_last_signature}\n")

def rsa_verify_gui():
    message = input_text.get("1.0", tk.END).strip()
    if rsa_last_signature is None:
        messagebox.showwarning("No Signature", "No RSA signature available. Sign first.")
        return
    valid = rsa_verify_signature(message, rsa_last_signature, rsa_public_key)
    result = "VALID" if valid else "INVALID"
    output_text.insert(tk.END, f"RSA Verification Result: {result}\n")

def ecc_sign_gui():
    global ecc_last_signature
    message = input_text.get("1.0", tk.END).strip()
    if not message:
        messagebox.showwarning("Input Required", "Please enter a message.")
        return
    ecc_last_signature = ecc_sign_message(message, ecc_private_key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "=== ECC Signing ===\n")
    output_text.insert(tk.END, f"ECC Signature: {ecc_last_signature.hex()}\n")

def ecc_verify_gui():
    message = input_text.get("1.0", tk.END).strip()
    if ecc_last_signature is None:
        messagebox.showwarning("No Signature", "No ECC signature available. Sign first.")
        return
    valid = ecc_verify_signature(message, ecc_last_signature, ecc_public_key)
    result = "VALID" if valid else "INVALID"
    output_text.insert(tk.END, f"ECC Verification Result: {result}\n")

def ecdh_key_exchange_gui():
    global shared_secret_alice, shared_secret_bob
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "=== ECDH Key Exchange ===\n")
    
    # Alice computes shared secret using her private key and Bob's public key
    shared_secret_alice = ecdh_compute_shared_secret(
        alice_ecdh_keys['private'], 
        bob_ecdh_keys['public']
    )
    
    # Bob computes shared secret using his private key and Alice's public key
    shared_secret_bob = ecdh_compute_shared_secret(
        bob_ecdh_keys['private'], 
        alice_ecdh_keys['public']
    )
    
    if shared_secret_alice and shared_secret_bob:
        output_text.insert(tk.END, f"Alice's computed shared secret: {shared_secret_alice.hex()}\n")
        output_text.insert(tk.END, f"Bob's computed shared secret: {shared_secret_bob.hex()}\n")
        
        # Verify both parties computed the same secret
        if shared_secret_alice == shared_secret_bob:
            output_text.insert(tk.END, "✅ SUCCESS: Both parties computed the same shared secret!\n")
            
            # Derive a symmetric key from the shared secret
            derived_key_alice = derive_key_from_shared_secret(shared_secret_alice, b'symmetric_key')
            derived_key_bob = derive_key_from_shared_secret(shared_secret_bob, b'symmetric_key')
            
            output_text.insert(tk.END, f"Derived symmetric key: {derived_key_alice.hex()}\n")
            output_text.insert(tk.END, "This key can now be used for symmetric encryption!\n")
        else:
            output_text.insert(tk.END, "❌ ERROR: Shared secrets don't match!\n")
    else:
        output_text.insert(tk.END, "❌ ERROR: Failed to compute shared secret!\n")

def generate_ecdh_keys_gui():
    global alice_ecdh_keys, bob_ecdh_keys
    
    alice_ecdh_keys = generate_ecdh_keypair()
    bob_ecdh_keys = generate_ecdh_keypair()
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "=== New ECDH Keys Generated ===\n")
    output_text.insert(tk.END, f"Alice's Public Key: {alice_ecdh_keys['public'].to_string().hex()}\n")
    output_text.insert(tk.END, f"Alice's Private Key: {alice_ecdh_keys['private'].to_string().hex()}\n")
    output_text.insert(tk.END, f"Bob's Public Key: {bob_ecdh_keys['public'].to_string().hex()}\n")
    output_text.insert(tk.END, f"Bob's Private Key: {bob_ecdh_keys['private'].to_string().hex()}\n")
    output_text.insert(tk.END, "\nNow you can perform ECDH key exchange!\n")

def show_ecdh_info():
    info_window = tk.Toplevel(root)
    info_window.title("ECDH Information")
    info_window.geometry("600x400")
    
    info_text = scrolledtext.ScrolledText(info_window, wrap=tk.WORD, width=70, height=25)
    info_text.pack(padx=10, pady=10, fill='both', expand=True)
    
    info_content = """ECDH (Elliptic Curve Diffie-Hellman) Key Exchange

What is ECDH?
ECDH is a key agreement protocol that allows two parties to establish a shared secret key over an insecure channel. It's based on the mathematical properties of elliptic curves.

How it works:
1. Alice generates a key pair (private key a, public key A = a*G)
2. Bob generates a key pair (private key b, public key B = b*G)
3. Alice and Bob exchange their public keys
4. Alice computes shared secret: S = a*B = a*(b*G) = (a*b)*G
5. Bob computes shared secret: S = b*A = b*(a*G) = (b*a)*G
6. Both parties now have the same shared secret S

Security:
- The shared secret is secure because an attacker would need to solve the Elliptic Curve Discrete Logarithm Problem (ECDLP)
- Even if an attacker intercepts both public keys, they cannot compute the shared secret without knowing at least one private key

Uses:
- Establishing symmetric encryption keys
- Secure communication protocols (TLS, VPN)
- Cryptocurrency transactions
- Secure messaging applications

In this tool:
- Alice and Bob represent two parties wanting to communicate securely
- After ECDH key exchange, they can use the derived key for symmetric encryption
- The tool demonstrates that both parties compute the same shared secret
"""
    
    info_text.insert(tk.END, info_content)
    info_text.config(state='disabled')

# ---------------------- GUI Setup ----------------------

root = tk.Tk()
root.title("Digital Signature & ECDH Tool (RSA, ECC, ECDH)")
root.geometry("900x700")
root.resizable(False, False)

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill='both', expand=True)

input_label = ttk.Label(main_frame, text="Enter Message:")
input_label.grid(row=0, column=0, sticky='w')

input_text = scrolledtext.ScrolledText(main_frame, width=100, height=5, wrap=tk.WORD)
input_text.grid(row=1, column=0, columnspan=6, pady=5)

# Button frames
btn_frame1 = ttk.Frame(main_frame)
btn_frame1.grid(row=2, column=0, columnspan=6, pady=5)

btn_frame2 = ttk.Frame(main_frame)
btn_frame2.grid(row=3, column=0, columnspan=6, pady=5)

# First row of buttons
keygen_btn = ttk.Button(btn_frame1, text="🔑 Generate All Keys", command=generate_keys_gui)
keygen_btn.grid(row=0, column=0, padx=5)

rsa_sign_btn = ttk.Button(btn_frame1, text="✍️ RSA Sign", command=rsa_sign_gui)
rsa_sign_btn.grid(row=0, column=1, padx=5)

rsa_verify_btn = ttk.Button(btn_frame1, text="✅ RSA Verify", command=rsa_verify_gui)
rsa_verify_btn.grid(row=0, column=2, padx=5)

ecc_sign_btn = ttk.Button(btn_frame1, text="✍️ ECC Sign", command=ecc_sign_gui)
ecc_sign_btn.grid(row=0, column=3, padx=5)

ecc_verify_btn = ttk.Button(btn_frame1, text="✅ ECC Verify", command=ecc_verify_gui)
ecc_verify_btn.grid(row=0, column=4, padx=5)

# Second row of buttons (ECDH)
ecdh_keygen_btn = ttk.Button(btn_frame2, text="🔐 Generate ECDH Keys", command=generate_ecdh_keys_gui)
ecdh_keygen_btn.grid(row=0, column=0, padx=5)

ecdh_exchange_btn = ttk.Button(btn_frame2, text="🤝 ECDH Key Exchange", command=ecdh_key_exchange_gui)
ecdh_exchange_btn.grid(row=0, column=1, padx=5)

ecdh_info_btn = ttk.Button(btn_frame2, text="ℹ️ ECDH Info", command=show_ecdh_info)
ecdh_info_btn.grid(row=0, column=2, padx=5)

output_label = ttk.Label(main_frame, text="Output:")
output_label.grid(row=4, column=0, sticky='w', pady=(10, 0))

output_text = scrolledtext.ScrolledText(main_frame, width=100, height=20, wrap=tk.WORD)
output_text.grid(row=5, column=0, columnspan=6, pady=5)

# Generate initial keys
generate_keys_gui()

root.mainloop()