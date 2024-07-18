import struct

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1_padding(message):
    message += b'\x80'
    
    # is congruent to 448 (mod 512)
    message += b'\x00' * ((56 - (len(message) % 64)) % 64)
    
    message_bit_length = len(message) * 8
    message += struct.pack('>Q', message_bit_length)
    
    return message

def sha1(message):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    message = sha1_padding(message)
    
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        
        w = [0] * 80
        
        for j in range(16):
            w[j] = struct.unpack('>I', chunk[j*4:j*4+4])[0]
        
        for j in range(16, 80):
            w[j] = left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
        
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        
        for j in range(80):
            if j < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif j < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            
            temp = left_rotate(a, 5) + f + e + k + w[j] & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp
        
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    return struct.pack('>5I', h0, h1, h2, h3, h4)

def sha1_digest(message):
    return sha1(message)
print("=========================================================")
print("SHA-1 Implementation - 2021BCY0033")
print("=========================================================")
message = input("Enter Text to Encrypt: ").encode()
digest = sha1_digest(message)
print('SHA-1 Digest:', digest.hex())
print("=========================================================")
