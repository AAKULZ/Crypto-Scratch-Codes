import numpy as np

s_box = [
    ['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5', '30', '01', '67', '2b', 'fe', 'd7', 'ab', '76'],
    ['ca', '82', 'c9', '7d', 'fa', '59', '47', 'f0', 'ad', 'd4', 'a2', 'af', '9c', 'a4', '72', 'c0'],
    ['b7', 'fd', '93', '26', '36', '3f', 'f7', 'cc', '34', 'a5', 'e5', 'f1', '71', 'd8', '31', '15'],
    ['04', 'c7', '23', 'c3', '18', '96', '05', '9a', '07', '12', '80', 'e2', 'eb', '27', 'b2', '75'],
    ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0', '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84'],
    ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b', '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf'],
    ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85', '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8'],
    ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5', 'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2'],
    ['cd', '0c', '13', 'ec', '5f', '97', '44', '17', 'c4', 'a7', '7e', '3d', '64', '5d', '19', '73'],
    ['60', '81', '4f', 'dc', '22', '2a', '90', '88', '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db'],
    ['e0', '32', '3a', '0a', '49', '06', '24', '5c', 'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79'],
    ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9', '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08'],
    ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6', 'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a'],
    ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e', '61', '35', '57', 'b9', '86', 'c1', '1d', '9e'],
    ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94', '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df'],
    ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68', '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']
]

# Inverse AES S-Box
inv_s_box = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
]

#r_con = [0x01000000,0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000, 0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000]
r_con = [
    '00000000', '01000000', '02000000', '04000000', '08000000', '10000000', '20000000', '40000000', '80000000', '1B000000', '36000000',
    '6C000000', 'D8000000', 'AB000000', '4D000000', '9A000000', '2F000000']

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

def decrypt_block(block, key):
    state = [block[i:i+2] for i in range(0, len(block), 2)]

    # Initial round
    state = add_round_key(state, key[10])
    state = [state[i:i+2] for i in range(0, len(state), 2)]
    print("Initial Round: ", state)

    # Main rounds in reverse order
    for i in range(9, 0, -4):
        state = inv_shift_rows(state)
        state = inv_substitute_bytes(state)
        state = add_round_key(state, key[i:i+4])
        state = mix_columns_inv(state)
        state = [state[i:i+2] for i in range(0, len(state), 2)]
        print(f"Round {(i // 4)}: \t", state)

    # Final round
    state = inv_shift_rows(state)
    state = inv_substitute_bytes(state)
    state = add_round_key(state, key[:4])
    state = [state[i:i+2] for i in range(0, len(state), 2)]
    print("Final Round: ", state)

    return [element for row in state for element in row]


def inv_shift_rows(state):
    state = [state[i:i+4] for i in range(0, len(state), 4)]
    state = [list(row) for row in zip(*state)]

    state[1] = np.roll(state[1], 1)
    state[2] = np.roll(state[2], 2)
    state[3] = np.roll(state[3], 3)
    state = [element for row in state for element in row]

    state = [state[i:i+4] for i in range(0, len(state), 4)]
    state = [list(row) for row in zip(*state)]

    return [element for row in state for element in row]


def inv_substitute_bytes(state):
    return [inv_s_box[int(hex_element[0], 16)][int(hex_element[1], 16)] for hex_element in state]


def mix_columns_inv(state):
    # Ensure state is a 2D list
    state = [state[i:i+4] for i in range(0, len(state), 4)]

    # Perform mix_columns_inv operation
    for i in range(4):
        s0 = int((state[i][0]), 16)
        s1 = int((state[i][1]), 16)
        s2 = int((state[i][2]), 16)
        s3 = int((state[i][3]), 16)

        # Perform inverse Galois Field multiplication
        result_0 = gmul(0x0E, s0) ^ gmul(0x0B, s1) ^ gmul(0x0D, s2) ^ gmul(0x09, s3)
        result_1 = gmul(0x09, s0) ^ gmul(0x0E, s1) ^ gmul(0x0B, s2) ^ gmul(0x0D, s3)
        result_2 = gmul(0x0D, s0) ^ gmul(0x09, s1) ^ gmul(0x0E, s2) ^ gmul(0x0B, s3)
        result_3 = gmul(0x0B, s0) ^ gmul(0x0D, s1) ^ gmul(0x09, s2) ^ gmul(0x0E, s3)

        # Convert the results to two-character hex representation
        state[i][0] = '{:02X}'.format(result_0)
        state[i][1] = '{:02X}'.format(result_1)
        state[i][2] = '{:02X}'.format(result_2)
        state[i][3] = '{:02X}'.format(result_3)

    # Flatten the 2D list back to a 1D list
    return [element.zfill(2) for row in state for element in row]


def decrypt(ciphertext, key):
    decrypted_blocks = []

    for block in ciphertext:
        decrypted_block = decrypt_block(block, key)
        decrypted_blocks.append(''.join(decrypted_block))

    return decrypted_blocks


def substitute_bytes(state):
    return [s_box[int(hex_element[0], 16)][int(hex_element[1], 16)] for hex_element in state]

def shift_rows(state):

    state = [state[i:i+4] for i in range(0, len(state), 4)]
    state = [list(row) for row in zip(*state)]

    state[1] = np.roll(state[1], -1)
    state[2] = np.roll(state[2], -2)
    state[3] = np.roll(state[3], -3)
    state = [element for row in state for element in row]

    state = [state[i:i+4] for i in range(0, len(state), 4)]
    state = [list(row) for row in zip(*state)]
 
    return [element for row in state for element in row]

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x11B  # XOR with irreducible polynomial
        b >>= 1
    return p % 256  # Ensure result is in the range [0, 255]

def mix_columns(state):
    # Ensure state is a 2D list
    state = [state[i:i+4] for i in range(0, len(state), 4)]

    # Perform mix_columns operation
    for i in range(4):
        s0 = int((state[i][0]), 16)
        s1 = int((state[i][1]), 16)
        s2 = int((state[i][2]), 16)
        s3 = int((state[i][3]), 16)

        # Perform Galois Field multiplication with irreducible polynomial
        result_0 = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3
        result_1 = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3
        result_2 = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3)
        result_3 = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3)

        # Convert the results to two-character hex representation
        state[i][0] = '{:02X}'.format(result_0)
        state[i][1] = '{:02X}'.format(result_1)
        state[i][2] = '{:02X}'.format(result_2)
        state[i][3] = '{:02X}'.format(result_3)


    # Flatten the 2D list back to a 1D list
    return [element.zfill(2) for row in state for element in row]

def add_round_key(state, round_key):
    round_key= ''.join(round_key)
    return hex(int((''.join(state)), 16) ^ int(round_key, 16))[2:].zfill(32)

def encrypt_block(block, key):
    state = [block[i:i+2] for i in range(0, len(block), 2)]
    # Initial round
    state = add_round_key(state, key[:4])
    state = [state[i:i+2] for i in range(0, len(state), 2)]
    print("Initial Round: ",state)
    
    # Main rounds
    for i in range(1, 41, 4):
        state = substitute_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        
        state = add_round_key(state, key[i:i+4])
        state = [state[i:i+2] for i in range(0, len(state), 2)]
        print(f"Round {(i // 4)+1}: \t",state)

    # Final round
    state = substitute_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key[10])
    state = [state[i:i+2] for i in range(0, len(state), 2)]
    print("Final Round: ",state)
    return [element for row in state for element in row]

def key_expansion(key, key_size):
    if key_size not in [128, 192, 256]:
        raise ValueError("Key size must be 128, 192, or 256 bits.")

    Nk = key_size // 32  # Number of 32-bit words in the key
    Nb = 4               # Number of columns (words) in the state array
    Nr = {128: 10, 192: 12, 256: 14}[key_size]  # Number of rounds

    # Initialize the key schedule with the original key
    w = [[key[i:i+2], key[i+2:i+4], key[i+4:i+6], key[i+6:i+8]] for i in range(0, len(key), 8)]

    # Key expansion core
    for i in range(Nk, Nb * (Nr + 1)):
        
        if i % Nk == 0:
            temp = w[i-1]
            temp = temp[1:] + [temp[0]]

            temp = [s_box[int(hex_element[0], 16)][int(hex_element[1], 16)] for hex_element in temp]
            temp = hex(int((''.join(temp)), 16) ^ int(r_con[i // Nk], 16))[2:]

        else:
            temp = ''.join(w[-1])
            
        hex_string=hex(int((''.join(w[i - Nk])), 16) ^ int(temp, 16))[2:]
        w.append([hex_string[i:i+2] for i in range(0, len(hex_string), 2)])


    round_keys_binary = ['{:032b}'.format(int(''.join(word), 16)) for word in w]
    round_keys_hex = [format(int(''.join(word), 16), '08X') for word in w]

    return round_keys_binary, round_keys_hex

def display_round_keys(round_keys_binary, round_keys_hex, words_per_round=4):
    for i in range(4, len(round_keys_binary), words_per_round):
        print(f"\nRound {i // words_per_round }:  {round_keys_hex[i:i+words_per_round]}")

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
    target_block_size = 32  #128 bit

    hex_representation = text_to_hex(plaintext)
    print("Text in Hexadecimal Format: ",hex_representation)
    blocks = split_into_blocks(hex_representation, target_block_size)

    print("--------------------------------------\n")
    print("Block Splitting according to block Size: \n")
    blocks[-1] = pad_last_block(blocks[-1], target_block_size)
    [print(block, end="\n") for block in blocks]
    print("--------------------------------------\n")
    
    key_size = int(input("Enter key size (128, 192, or 256): "))

    if key_size not in [128, 192, 256]:
        print("Invalid key size. Choose 128, 192, or 256.")
        key_size = int(input("Enter key size (128, 192, or 256): "))

    key = np.random.randint(0, 256, size=key_size // 8, dtype=np.uint8)
    key = ''.join(format(num, '02X') for num in key)
    print("--------------------------------------\n")
    print("Key:", key)
    round_keys_binary, round_keys_hex = key_expansion(key, key_size)
  
    display_round_keys(round_keys_binary, round_keys_hex)
    print("--------------------------------------\n")
    
    print("Plaintext:", plaintext)
    print("Key:", key)
    print("--------------------------------------")
    print("\nEncryption:\n")

    ciphertext = ""
    decipher=blocks.copy()
    i=0

    for block in blocks:
        print(f"Block-{i+1}: \n")
        block_ciphertext = encrypt_block(block, round_keys_hex)

        ciphertext += ''.join(block_ciphertext)
        print("\nCiphertext:",ciphertext)
  
        i+=1
        print("--------------------------------------\n")
if __name__ == "__main__":
    main()
