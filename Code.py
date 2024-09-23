# 1. Define Block and Key Sizes
BLOCK_SIZE = 8  # Each block is 8 bits (1 byte)
KEY_SIZE = 8    # The key is also 8 bits

# 2. Define Substitution Box (S-box)
S_BOX = [0xE, 0x4, 0xD, 0x1,
         0x2, 0xF, 0xB, 0x8,
         0x3, 0xA, 0x6, 0xC,
         0x5, 0x9, 0x0, 0x7]

# Function to substitute 4-bit values using the S-box
def substitute_4bits(input_value):
    """Substitute 4-bit value using S-Box"""
    return S_BOX[input_value]

# 3. Define Permutation Function
PERMUTATION_TABLE = [2, 6, 4, 1, 3, 7, 0, 5]  

# Function to permute an 8-bit block according to the permutation table
def permute(block):
    """Permute 8-bit block using the permutation table"""
    block_str = f'{block:08b}'  
    permuted = ''.join([block_str[PERMUTATION_TABLE[i]] for i in range(BLOCK_SIZE)])
    return int(permuted, 2)

# 4. Feistel Function
def feistel_function(right_half, key):
    """Feistel function: XOR right half of the block with the key"""
    return right_half ^ key

# 5. Combine Components for Single-Round Encryption
def encrypt_block(plaintext, key):
    """Encrypt a single 8-bit block"""
    left_half = (plaintext >> 4) & 0xF  # Top 4 bits
    right_half = plaintext & 0xF  # Bottom 4 bits
    
    right_half_sub = substitute_4bits(right_half)
    feistel_out = feistel_function(left_half, right_half_sub)
    
    combined = (feistel_out << 4) | right_half_sub
    permuted_block = permute(combined)
    
    return permuted_block

# ECB Mode Implementation
def ecb_mode_encrypt(plaintext_blocks, key):
    """Encrypt multiple blocks in ECB mode"""
    return [encrypt_block(block, key) for block in plaintext_blocks]

def ecb_mode_decrypt(ciphertext_blocks, key):
    """Decrypt multiple blocks in ECB mode"""
    return [encrypt_block(block, key) for block in ciphertext_blocks]

# CBC Mode Implementation
def xor_blocks(block1, block2):
    """XOR two 8-bit blocks"""
    return block1 ^ block2

def cbc_mode_encrypt(plaintext_blocks, key, iv):
    """Encrypt multiple blocks in CBC mode"""
    ciphertext_blocks = []
    previous_block = iv
    for block in plaintext_blocks:
        block_to_encrypt = xor_blocks(block, previous_block)
        encrypted_block = encrypt_block(block_to_encrypt, key)
        ciphertext_blocks.append(encrypted_block)
        previous_block = encrypted_block
    return ciphertext_blocks

def cbc_mode_decrypt(ciphertext_blocks, key, iv):
    """Decrypt multiple blocks in CBC mode"""
    plaintext_blocks = []
    previous_block = iv
    for block in ciphertext_blocks:
        decrypted_block = encrypt_block(block, key)
        plaintext_block = xor_blocks(decrypted_block, previous_block)
        plaintext_blocks.append(plaintext_block)
        previous_block = block
    return plaintext_blocks

# Example usage for ECB and CBC modes
def example_run():
    # Test data with different values
    plain_blocks = [0b11010010, 0b00110111, 0b01010101]  # Three 8-bit blocks (210, 55, and 85 in decimal)
    key_val = 0b11100001                              # New 8-bit key
    iv_val = 0b00001111                               # New initialization vector

    # ECB Mode Example
    print("ECB Mode Encryption:")
    encrypted_ecb = ecb_mode_encrypt(plain_blocks, key_val)
    print(f"ECB Ciphertext: {[bin(c) for c in encrypted_ecb]}")

    decrypted_ecb = ecb_mode_decrypt(encrypted_ecb, key_val)
    print(f"ECB Decrypted: {[bin(d) for d in decrypted_ecb]}")

    # CBC Mode Example
    print("\nCBC Mode Encryption:")
    encrypted_cbc = cbc_mode_encrypt(plain_blocks, key_val, iv_val)
    print(f"CBC Ciphertext: {[bin(c) for c in encrypted_cbc]}")

    decrypted_cbc = cbc_mode_decrypt(encrypted_cbc, key_val, iv_val)
    print(f"CBC Decrypted: {[bin(d) for d in decrypted_cbc]}")

if __name__ == "__main__":
    example_run()
