import random
import string

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

def permute(block, table):
    return [block[i - 1] for i in table]

def string_to_bits(text):
    bits = []
    for char in text:
        byte = format(ord(char), '08b')
        bits.extend([int(b) for b in byte])
    return bits

def bits_to_string(bits):
    text = ""
    for i in range(0, len(bits), 8):
        if i + 8 <= len(bits):
            byte = bits[i:i+8]
            char_code = 0
            for j, bit in enumerate(byte):
                char_code += bit * (2 ** (7-j))
            text += chr(char_code)
    return text

def pad_text(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def simple_xor_with_key(data, key):
    key_bits = string_to_bits(key[:8])
    
    if len(key_bits) < 64:
        key_bits.extend([0] * (64 - len(key_bits)))
    else:
        key_bits = key_bits[:64]
    
    result = [data[i] ^ key_bits[i] for i in range(64)]
    return result

def simple_encrypt(plaintext, key):
    plaintext_bits = string_to_bits(plaintext)
    
    if len(plaintext_bits) < 64:
        plaintext_bits.extend([0] * (64 - len(plaintext_bits)))
    else:
        plaintext_bits = plaintext_bits[:64]
    
    after_ip = permute(plaintext_bits, IP)
    
    after_xor = simple_xor_with_key(after_ip, key)
    
    final_block = permute(after_xor, FP)
    return final_block

def simple_decrypt(ciphertext, key):
    after_ip = permute(ciphertext, IP)
    
    after_xor = simple_xor_with_key(after_ip, key)
    
    final_block = permute(after_xor, FP)
    return final_block

def interactive_mode():    
    while True:
        print("\nOptions:")
        print("1. Encrypte/Decrypt")
        print("2. Exit")
        
        choice = input("Choose (1-2): ").strip()
        
        if choice == '1':
            while True:
                text = input("Enter text to encrypt (must be exactly 8 characters): ")
                if len(text) == 8:
                    break
                else:
                    print(f"The message should be exactly 8 characters.")
                    print("Please try again.")
            
            key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            
            print(f"Original Text: {text}")
            print(f"Auto-generated Key: {key}")
            
            print("\nEncrypting...")
            encrypted_bits = simple_encrypt(text[:8], key)
            
            hex_result = ""
            for i in range(0, len(encrypted_bits), 4):
                if i + 4 <= len(encrypted_bits):
                    nibble = encrypted_bits[i:i+4]
                    hex_val = nibble[0]*8 + nibble[1]*4 + nibble[2]*2 + nibble[3]
                    hex_result += format(hex_val, 'X')
            
            binary_string = ''.join(map(str, encrypted_bits))
            
            print(f"Ciphertext (binary): {binary_string}")
            print(f"Ciphertext (hex): {hex_result}")
            
            print("\nDecrypting to verify...")
            decrypted_bits = simple_decrypt(encrypted_bits, key)
            decrypted_text = bits_to_string(decrypted_bits)
            
            decrypted_binary = ''.join(map(str, decrypted_bits))
            
            print(f"Decrypted bits (binary): {decrypted_binary}")
            print(f"Decrypted text: {decrypted_text}")
            
            print("\n" + "="*50)
            if decrypted_text.strip() == text.strip():
                print("VERIFICATION: SUCCESS - Decryption matches original!")
            else:
                print("VERIFICATION: FAILED - Decryption does not match!")
            print("="*50)
                
        elif choice == '2':
            print("Goodbye!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    interactive_mode()