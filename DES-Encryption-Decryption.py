def hex_to_bin(hex_string):
    binary_map = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
              '4': "0100", '5': "0101", '6': "0110", '7': "0111",
              '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
              'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111",
              'a': "1010", 'b': "1011", 'c': "1100", 'd': "1101",
              'e': "1110", 'f': "1111", ' ': " "}

    binary_result = ""
    for char in hex_string:
        binary_result += binary_map[char]

    return binary_result

def bin_to_hex(binary_string):
    hex_map = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
               "0100": '4', "0101": '5', "0110": '6', "0111": '7',
               "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
               "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}

    hex_result = ""
    for i in range(0, len(binary_string), 4):
        chunk = ""
        chunk = chunk + binary_string[i:i + 4]
        hex_result += hex_map[chunk]

    return hex_result

def bin_to_dec(binary):
    binary_str = str(binary)
    decimal, i = 0, 0

    while binary != 0:
        dec = binary % 10
        decimal += dec * 2**i
        binary //= 10
        i += 1

    return decimal

def dec_to_bin(number):
    binary_result = bin(number).replace("0b", "")

    if len(binary_result) % 4 != 0:
        div = len(binary_result) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(binary_result)
        
        for i in range(0, counter):
            binary_result = '0' + binary_result

    return binary_result

def hex_to_text(hex_string):
    try:
        byte_data = bytes.fromhex(hex_string)

        text_data = byte_data.decode('utf-8')
        return text_data
    except ValueError:
        print("Invalid hex string.")
        return None

def permute(data, permutation_table, size):
    result = ""
    for i in range(size):
        result += data[permutation_table[i] - 1]

    return result

def shift_left(data, shifts):
    for i in range(shifts):
        data = data[1:] + data[0]

    return data

def xor(a, b):
    result = ""
    for i in range(len(a)):
        result += '0' if a[i] == b[i] else '1'

    return result

def encrypt(plaintext, round_key_bits, round_key_hex):
    plaintext = hex_to_bin(plaintext)

    # Initial Permutation
    plaintext = permute(plaintext, initial_permutation_table, 64)
    print("After initial permutation", bin_to_hex(plaintext))

    # Splitting
    left = plaintext[0:32]
    right = plaintext[32:64]

    for i in range(16):
        # Expansion D-box
        right_expanded = permute(right, expansion_d_box_table, 48)

        # XOR RoundKey[i] and right_expanded
        xor_result = xor(right_expanded, round_key_bits[i])

        # S-box substitution
        sbox_str = ""
        for j in range(8):
            row = bin_to_dec(int(xor_result[j * 6] + xor_result[j * 6 + 5]))
            col = bin_to_dec(int(xor_result[j * 6 + 1] + xor_result[j * 6 + 2] + xor_result[j * 6 + 3] + xor_result[j * 6 + 4]))
            val = sbox[j][row][col]
            sbox_str += dec_to_bin(val)

        # Straight D-box
        sbox_str = permute(sbox_str, straight_d_box_table, 32)

        # XOR left and sbox_str
        result = xor(left, sbox_str)
        left = result

        # Swap left and right every round except the last one
        if i != 15:
            left, right = right, left

        print("Round", i + 1, bin_to_hex(left), bin_to_hex(right), round_key_hex[i])

    # Combination
    combined = left + right

    # Final permutation
    ciphertext = permute(combined, final_permutation_table, 64)
    return ciphertext

# Constants
initial_permutation_table = [58, 50, 42, 34, 26, 18, 10, 2,
                              60, 52, 44, 36, 28, 20, 12, 4,
                              62, 54, 46, 38, 30, 22, 14, 6,
                              64, 56, 48, 40, 32, 24, 16, 8,
                              57, 49, 41, 33, 25, 17, 9, 1,
                              59, 51, 43, 35, 27, 19, 11, 3,
                              61, 53, 45, 37, 29, 21, 13, 5,
                              63, 55, 47, 39, 31, 23, 15, 7]

expansion_d_box_table = [32, 1, 2, 3, 4, 5, 4, 5,
                         6, 7, 8, 9, 8, 9, 10, 11,
                         12, 13, 12, 13, 14, 15, 16, 17,
                         16, 17, 18, 19, 20, 21, 20, 21,
                         22, 23, 24, 25, 24, 25, 26, 27,
                         28, 29, 28, 29, 30, 31, 32, 1]

straight_d_box_table = [16, 7, 20, 21,
                        29, 12, 28, 17,
                        1, 15, 23, 26,
                        5, 18, 31, 10,
                        2, 8, 24, 14,
                        32, 27, 3, 9,
                        19, 13, 30, 6,
                        22, 11, 4, 25]

final_permutation_table = [40, 8, 48, 16, 56, 24, 64, 32,
                           39, 7, 47, 15, 55, 23, 63, 31,
                           38, 6, 46, 14, 54, 22, 62, 30,
                           37, 5, 45, 13, 53, 21, 61, 29,
                           36, 4, 44, 12, 52, 20, 60, 28,
                           35, 3, 43, 11, 51, 19, 59, 27,
                           34, 2, 42, 10, 50, 18, 58, 26,
                           33, 1, 41, 9, 49, 17, 57, 25]

sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

key_generation_parity_drop_table = [57, 49, 41, 33, 25, 17, 9,
                                    1, 58, 50, 42, 34, 26, 18,
                                    10, 2, 59, 51, 43, 35, 27,
                                    19, 11, 3, 60, 52, 44, 36,
                                    63, 55, 47, 39, 31, 23, 15,
                                    7, 62, 54, 46, 38, 30, 22,
                                    14, 6, 61, 53, 45, 37, 29,
                                    21, 13, 5, 28, 20, 12, 4]

key_generation_shift_table = [1, 1, 2, 2,
                              2, 2, 2, 2,
                              1, 2, 2, 2,
                              2, 2, 2, 1]

key_generation_compression_table = [14, 17, 11, 24, 1, 5,
                                    3, 28, 15, 6, 21, 10,
                                    23, 19, 12, 4, 26, 8,
                                    16, 7, 27, 20, 13, 2,
                                    41, 52, 31, 37, 47, 55,
                                    30, 40, 51, 45, 33, 48,
                                    44, 49, 39, 56, 34, 53,
                                    46, 42, 50, 36, 29, 32]

def generate_round_keys(key):
    key_binary = hex_to_bin(key)
    key_binary = permute(key_binary, key_generation_parity_drop_table, 56)

    left = key_binary[0:28]
    right = key_binary[28:56]

    round_keys_binary = []

    for i in range(16):
        left = shift_left(left, key_generation_shift_table[i])
        right = shift_left(right, key_generation_shift_table[i])

        combined = left + right
        round_key = permute(combined, key_generation_compression_table, 48)

        round_keys_binary.append(round_key)

    round_keys_hex = [bin_to_hex(key) for key in round_keys_binary]
    return round_keys_binary, round_keys_hex

def decrypt(ciphertext, round_keys_binary, round_keys_hex):
    # Initial Permutation
    ciphertext = permute(ciphertext, initial_permutation_table, 64)

    # Splitting
    left = ciphertext[0:32]
    right = ciphertext[32:64]

    for i in range(15, -1, -1):
        # Expansion D-box
        right_expanded = permute(right, expansion_d_box_table, 48)

        # XOR RoundKey[i] and right_expanded
        xor_result = xor(right_expanded, round_keys_binary[i])

        # S-box substitution
        sbox_str = ""
        for j in range(8):
            row = bin_to_dec(int(xor_result[j * 6] + xor_result[j * 6 + 5]))
            col = bin_to_dec(int(xor_result[j * 6 + 1] + xor_result[j * 6 + 2] + xor_result[j * 6 + 3] + xor_result[j * 6 + 4]))
            val = sbox[j][row][col]
            sbox_str += dec_to_bin(val)

        # Straight D-box
        sbox_str = permute(sbox_str, straight_d_box_table, 32)

        # XOR left and sbox_str
        result = xor(left, sbox_str)
        left = result

        # Swap left and right every round except the last one
        if i != 0:
            left, right = right, left

    # Combination
    combined = left + right

    # Final permutation
    plaintext = permute(combined, final_permutation_table, 64)
    return plaintext

def text_to_hex(text):
    hex_representation = text.encode().hex()
    return hex_representation

def split_into_blocks(hex_string, block_size):
    return [hex_string[i:i+block_size] for i in range(0, len(hex_string), block_size)]

def pad_last_block(block, target_size):
    return block.ljust(target_size, '0')

    
def main():
    print("--------------------------------------")
    plaintext = input("Enter the plaintext: ")
    target_block_size = 16  

    hex_representation = text_to_hex(plaintext)
    print("Text in Hexadecimal Format: ",hex_representation)
    blocks = split_into_blocks(hex_representation, target_block_size)
    print(blocks)
    blocks[-1] = pad_last_block(blocks[-1], target_block_size)
    key = "AABB09182736CCDD"
    
    round_keys_binary, round_keys_hex = generate_round_keys(key)
    
    print("Plaintext:", plaintext)
    print("Key:", key)
    print("--------------------------------------")
    print("\nEncryption:\n")

    ciphertext = ""
    decipher=blocks.copy()
    i=0

    for block in blocks:
        print(f"Block-{i+1}: \n")
        block_ciphertext = encrypt(block, round_keys_binary, round_keys_hex)

        ciphertext += bin_to_hex(block_ciphertext)
        decipher[i]=bin_to_hex(block_ciphertext)
        i+=1
        print("--------------------------------------\n")
    
    print("\nCiphertext:",ciphertext)

    print("--------------------------------------")
    print("\nDecryption:\n")

    decrypted_text = ""
    i = 1

    for block in decipher:
        print(f"Block-{i}: \n")
        block_decrypted = encrypt(block, round_keys_binary[::-1], round_keys_hex[::-1])
        print("--------------------------------------\n")

        decrypted_text += block_decrypted
        i += 1
    print("\nDecrypted Text:", hex_to_text(bin_to_hex(decrypted_text)))
    print("--------------------------------------\n")
    

if __name__ == "__main__":
    main()
