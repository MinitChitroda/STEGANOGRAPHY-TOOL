import os
from PIL import Image
import numpy as np
from pathlib import Path
import tkinter as tk
from tkinter import filedialog

def select_image():
    root = tk.Tk()
    root.withdraw()  
    file_path = filedialog.askopenfilename(
        title="Select Image",
        filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
    )
    return file_path if file_path else None

def encrypt_image(image_path, message, key):
    # Load the image
    img = Image.open(image_path)
    pixels = np.array(img) #converts to pixel for pixel manipulation

    message += "$$END$$"  # Add end marker to the message
    binary_message = ""
    for i, char in enumerate(message):
        encrypted_char = ord(char) ^ ord(key[i % len(key)])  # XOR with key
        binary_message += f"{encrypted_char:08b}"  # Convert to 8-bit binary

    # Check if the message fits in the image
    if len(binary_message) > pixels.size:
        raise ValueError("Message is too large to fit in this image.")

    # Modify the image's pixel values to hide the message
    flat_pixels = pixels.flatten()
    for i in range(len(binary_message)):
        # Set the least significant bit to the current binary message bit
        flat_pixels[i] = (flat_pixels[i] & ~1) | int(binary_message[i]) # & ~1 for bitwise not on 1 to clear off the LSB and make it 0. and then perfrom OR operation with the message bit to make it modified pixel 

    # Reshape the modified pixels back to the original image dimensions
    modified_pixels = flat_pixels.reshape(pixels.shape)

    # Save the modified image
    output_dir = Path("hided_imgs")
    output_dir.mkdir(exist_ok=True)

    return Image.fromarray(modified_pixels) #converts the modified pixel to image


def decrypt_image(image_path, key):
    try:
        # Open the image and convert to NumPy array
        img = Image.open(image_path) 
        pixels = np.array(img) #converts to pixel for pixel manipulation

        # Extract binary data from the least significant bits
        binary_message = []
        flat_pixels = pixels.flatten() 

        for pixel in flat_pixels:
            binary_message.append(str(pixel & 1)) #extracts the LSB of each pixel and appends it to the binary_message

            if len(binary_message) % 8 == 0: #if the length of the binary_message is a multiple of 8, then it means a byte has been extracted
                # Convert binary to text so far
                text = ""
                for i in range(0, len(binary_message), 8):
                    byte = ''.join(binary_message[i:i + 8])
                    char = chr(int(byte, 2) ^ ord(key[i // 8 % len(key)]))
                    text += char

                    # Stop if the end marker is found
                    if "$$END$$" in text:
                        return True, text.split("$$END$$")[0]

                # If characters decoded so far look nonsensical, stop early
                if not text.isprintable():
                    return False, "Incorrect decryption key."

        # If the loop completes without finding the end marker
        return False, "No valid hidden message found."

    except Exception as e:
        # Handle exceptions during decryption
        return False, f"Error during decryption: {str(e)}"


def main():
    print("\n=== Steganography Tool ===")
    print("1. Encrypt message in image")
    print("2. Decrypt message from image")
    print("Press q to quit")

    
    choice = input("\nEnter your choice (1 or 2):" ).strip().lower()
    
    try:
        if choice == "1":
            
            print("\n--- Encryption Mode ---")
            print("\nPlease select an image file...")
            image_path = select_image()
            if not image_path:
                print("No image selected. Exiting...")
                return
            

            message = input("\nEnter the secret message: ").strip()
            key = input("Enter the encryption key: ").strip()
            
            if not message or not key:
                print("Message and key cannot be empty!")
                return
            
            
            output_name = input("\nEnter name for the output image (without extension): ").strip()
            if not output_name:
                output_name = "encrypted"
            
            output_path = Path("hided_imgs") / f"{output_name}.png"
            
            
            encrypted_image = encrypt_image(image_path, message, key)
            encrypted_image.save(output_path)
            
            print(f"\nSuccess! Encrypted image saved as: {output_path}")
            
        elif choice == "2":
            
            print("\n--- Decryption Mode ---")
            
            
            print("\nPlease select the encrypted image...")
            image_path = select_image()
            if not image_path:
                print("No image selected. Exiting...")
                return
            
            
            key = input("\nEnter the decryption key: ").strip()
            if not key:
                print("Key cannot be empty!")
                return
            
            
            success, result = decrypt_image(image_path, key)
            
            if success:
                print(f"\nDecrypted message: {result}")
            else:
                print(f"\nDecryption failed: {result}")
        
        elif choice == "q":
            print("Exiting...")
            return
    
        else:
            print("Invalid choice! Please select 1 or 2.")
            
    except Exception as e:
        print(f"\nError: {str(e)}")
        
if __name__ == "__main__":
    main()