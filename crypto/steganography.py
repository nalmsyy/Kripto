from PIL import Image
import os

def text_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

def binary_to_text(binary_data):
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

def encode_image(image_path, secret_message, output_path):
    """
    Menyisipkan pesan rahasia ke dalam gambar menggunakan LSB.
    """
    try:
        img = Image.open(image_path)
        img = img.convert("RGB")
        width, height = img.size
        pixels = img.load()

        # Delimiter unik untuk menandai akhir pesan
        delimiter = "1111111111111110" 
        binary_message = text_to_binary(secret_message) + delimiter

        if len(binary_message) > width * height:
            raise ValueError("Pesan terlalu panjang untuk gambar ini.")

        data_index = 0
        message_len = len(binary_message)

        for y in range(height):
            for x in range(width):
                if data_index < message_len:
                    r, g, b = pixels[x, y]
                    
                    # Ubah LSB pada channel Red
                    original_r_bin = format(r, '08b')
                    bit_to_hide = binary_message[data_index]
                    new_r = int(original_r_bin[:-1] + bit_to_hide, 2)
                    
                    pixels[x, y] = (new_r, g, b)
                    data_index += 1
                else:
                    break
        
        img.save(output_path)
        return True
    except Exception as e:
        print(f"Error Stegano Encode: {e}")
        return False

def decode_image(image_path):
    """
    Mengekstrak pesan rahasia dari gambar LSB.
    """
    try:
        img = Image.open(image_path)
        img = img.convert("RGB")
        pixels = img.load()
        width, height = img.size

        binary_data = ""
        delimiter = "1111111111111110"
        
        found = False

        for y in range(height):
            if found: break
            for x in range(width):
                r, g, b = pixels[x, y]
                # Ambil LSB
                extracted_bit = format(r, '08b')[-1]
                binary_data += extracted_bit

                if binary_data.endswith(delimiter):
                    found = True
                    break
        
        if found:
            final_binary = binary_data[:-len(delimiter)]
            return binary_to_text(final_binary)
        return None
    except Exception as e:
        print(f"Error Stegano Decode: {e}")
        return None