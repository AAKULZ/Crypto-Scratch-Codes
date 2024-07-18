import random
import math

primes_set = set()


def generate_primes():
    sieve = [True] * 250
    sieve[0] = False
    sieve[1] = False
    
    for i in range(2, 250):
        for j in range(i * 2, 250, i):
            sieve[j] = False
    
    for i in range(len(sieve)):
        if sieve[i]:
            primes_set.add(i)

def pick_random_prime():
    global primes_set
    k = random.randint(0, len(primes_set) - 1)
    it = iter(primes_set)
    
    for _ in range(k):
        next(it)
    
    ret = next(it)
    primes_set.remove(ret)
    return ret

def set_keys():
    global public_key_val, private_key_val, modulus_n, prime1, prime2
    prime1 = pick_random_prime()
    prime2 = pick_random_prime()
    
    modulus_n = prime1 * prime2
    fi = (prime1 - 1) * (prime2 - 1)
    
    e = 2
    while True:
        if math.gcd(e, fi) == 1:
            break
        e += 1
    
    public_key_val = e
    
    d = 2
    while True:
        if (d * e) % fi == 1:
            break
        d += 1
    
    private_key_val = d

def encrypt_message(msg):
    global public_key_val, modulus_n
    e = public_key_val
    encrypted_text = 1
    
    while e > 0:
        encrypted_text *= msg
        encrypted_text %= modulus_n
        e -= 1
    
    return encrypted_text

def encrypt_message(msg):
    global public_key_val, modulus_n
    e = public_key_val
    encrypted_text = 1
    
    while e > 0:
        encrypted_text *= msg
        encrypted_text %= modulus_n
        e -= 1
    
    return encrypted_text

def decrypt_message(encrypted_text):
    global private_key_val, modulus_n
    d = private_key_val
    decrypted = 1
    
    while d > 0:
        decrypted *= encrypted_text
        decrypted %= modulus_n
        d -= 1
    
    return decrypted

def encode_message(message):
    encoded_msg = []
    
    for letter in message:
        encoded_msg.append(encrypt_message(ord(letter)))
    
    return encoded_msg

def decode_message(encoded_msg):
    decoded_str = ''
    
    for num in encoded_msg:
        decoded_str += chr(decrypt_message(num))
    
    return decoded_str

if __name__ == '__main__':
    global public_key_val, private_key_val, modulus_n, prime1, prime2
    generate_primes()
    set_keys()
    print("========================================================")
    print("RSA ENCRYPTION AND DECRYPTION")
    print("--------------------------------------------------------")
    print("Generated Primes: ")
    print("P: ",prime1)
    print("Q: ",prime2)
    f=prime1*prime2
    print("Modulus N [P*Q]: ",f)
    print("FI Value: ",(prime1-1)*(prime2-1))
    print("--------------------------------------------------------")
    print("Keys: ")
    print(f"Public Key: [{public_key_val},{f}]")
    print(f"Private Key: [{private_key_val},{f}]")
    print("========================================================")
    
    original_message = input("Input Message: ")
    
    encoded_message = encode_message(original_message)
    
    print("Initial message:")
    print(original_message)
    print("\nEncrypted message(encrypted by public key): ",end="")
    print(''.join(str(p) for p in encoded_message))
    print("\nDecrypted message(decrypted by public key): ",end="")
    print(''.join(str(p) for p in decode_message(encoded_message)))
    print("========================================================")
