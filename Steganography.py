import cv2
import os
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

def encrypt_message(message, password):
    """Encrypt the message using XOR encryption with the password."""
    return "".join(chr(ord(c) ^ ord(password[i % len(password)])) for i, c in enumerate(message))

def decrypt_message(encrypted, password):
    """Decrypt the message using XOR encryption with the password."""
    return encrypt_message(encrypted, password)  # XOR reverses itself

def encode_message():
    file_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("JPEG Files", "*.jpg"), ("PNG Files", "*.png")])
    if not file_path:
        return
    
    img = cv2.imread(file_path)
    msg = simpledialog.askstring("Input", "Enter secret message:")
    password = simpledialog.askstring("Input", "Enter a passcode:", show='*')
    
    if not msg or not password:
        messagebox.showerror("Error", "Message or password cannot be empty!")
        return

    encrypted_msg = encrypt_message(msg, password)
    binary_msg = ''.join(format(ord(c), '08b') for c in encrypted_msg)  # Convert message to binary

    if len(binary_msg) > img.size * 3:
        messagebox.showerror("Error", "Message too large for the image!")
        return

    binary_len = format(len(binary_msg), '032b')  # Store length as 32-bit binary
    binary_msg = binary_len + binary_msg

    index = 0
    for row in img:
        for pixel in row:
            for i in range(3):  # Iterate through RGB channels
                if index < len(binary_msg):
                    pixel[i] = (int(pixel[i]) & ~1) | int(binary_msg[index])  # Fixed OverflowError
                    index += 1

    output_path = "encoded_image.png"
    cv2.imwrite(output_path, img)
    os.system(f"start {output_path}")  # Open image on Windows
    messagebox.showinfo("Success", f"Message encoded and saved as {output_path}")

def decode_message():
    file_path = filedialog.askopenfilename(title="Select Encoded Image", filetypes=[("JPEG Files", "*.jpg"), ("PNG Files", "*.png")])
    if not file_path:
        return

    img = cv2.imread(file_path)
    password = simpledialog.askstring("Input", "Enter passcode for decryption:", show='*')

    if not password:
        messagebox.showerror("Error", "Password cannot be empty!")
        return

    binary_data = ""
    for row in img:
        for pixel in row:
            for i in range(3):  # Iterate through RGB channels
                binary_data += str(pixel[i] & 1)

    message_len = int(binary_data[:32], 2)  # Extract 32-bit length
    binary_msg = binary_data[32:32 + message_len]

    decrypted_msg = "".join(chr(int(binary_msg[i:i+8], 2)) for i in range(0, len(binary_msg), 8))
    decrypted_msg = decrypt_message(decrypted_msg, password)  # Decrypt the message
    messagebox.showinfo("Decoded Message", f"Message: {decrypted_msg}")

root = tk.Tk()
root.title("Steganography Tool")

tk.Button(root, text="Encode Message", command=encode_message).pack(pady=10)
tk.Button(root, text="Decode Message", command=decode_message).pack(pady=10)

root.mainloop()
