import random
import sympy
import hashlib

def mod_exp(base, exp, mod):
    # Modular exponentiation
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def gcd(a, b):
    # Euclidean algorithm to compute gcd
    while b != 0:
        a, b = b, a % b
    return a

def find_primitive_root(p):
    if p == 2:
        return 1

    # Check if p is a prime number
    if not sympy.isprime(p):
        raise ValueError("Input must be a prime number.")

    phi = p - 1  # Euler's totient function

    # Find the prime factors of phi
    factors = prime_factors_of_phi(phi)
    

    # Check for primitive roots by brute force
    for g in range(2, p):
        is_primitive = True
        for factor in factors:
            if mod_exp(g, (p - 1) // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return g

    return None

# Function to find prime factors of a number
def prime_factors_of_phi(phi):
    factors=[]
    for i in range(2, int(phi**0.5) + 1):
        if phi % i == 0:
            factors.append(i)
            while phi % i == 0:
                phi //= i
    if phi > 1:
        factors.append(phi)
    return factors
                                 
def generate_n_bit_prime(bits):
    while True:                                              
        # Generate a random 128-bit odd number
        num = random.getrandbits(bits)
        num |= (1 << (bits - 1)) | 1  # Set the most significant and least significant bits to 1 to ensure a 128-bit number
        if sympy.isprime(num):
            return num

# Diffie-Hellman key exchange
def diffie_hellman(p, g):

    p_subscript = ''.join(chr(0x2080 + int(d)) for d in str(p))   # Convert digits to subscript Unicode characters
    #p_superscript = ''.join(chr(0x2070 + int(d)) for d in str(p))  # Convert digits to superscript Unicode characters
    superstring_digits = ["⁰", "¹", "²", "³", "⁴", "⁵", "⁶", "⁷", "⁸", "⁹"]

    digits = [int(digit) for digit in str(p)]
    p_superscript = ''.join(superstring_digits[d] for d in digits)

    # Alice generates her private key
    alice_private_key = random.randint(2, p - 2)
    # Bob generates his private key
    bob_private_key = random.randint(2, p - 2)

    # Alice computes her public key
    alice_public_key = pow(g,alice_private_key,p)
    # Bob computes his public key
    bob_public_key = pow(g,bob_private_key,p)

    print("\n---------------------------------------------------------------------------")
    print("Alice Keys: ")

    print(f"Private Key [x <- Z*{p_subscript}]: ", alice_private_key)
    print(f"Public Key [h1 = g{p_superscript}]:", alice_public_key)
    print("---------------------------------------------------------------------------")


    print(f"\nAlice-------(G: Z*{p_subscript},g: {g},q: {p},h1: g{p_superscript})------->Bob")
    
    print("\n---------------------------------------------------------------------------")
    print("Bob Keys: ")

    print(f"Private Key [y <- Z*{p_subscript}]:", bob_private_key)
    print(f"Public Key [h1 = g{p_superscript}]:", bob_public_key)
    print("---------------------------------------------------------------------------")

    print(f"\nAlice<------------------------------(h2:{g})------------------------------Bob")

    
    # Alice computes the shared secret
    secret_A = pow(bob_public_key, alice_private_key, p)
    # Bob computes the shared secret
    secret_B = pow(alice_public_key, bob_private_key, p)

    # Both shared secrets should be the same
    assert secret_A == secret_B
    shared_secret_inverse = mod_exp(bob_public_key,alice_private_key , p)
    print(f"\nAlice<------------------==(Shared Secret [g^xy]: {g})==------------------>Bob")
    
    return secret_A,shared_secret_inverse,

# ElGamal encryption
def asymmetric_encrypt(msg, shared_secret):
    encrypted_msg = []

    for char in msg:
        encrypted_msg.append(shared_secret * ord(char))

    for i in range(len(encrypted_msg)):
        encrypted_msg[i] = encrypted_msg[i]

    return encrypted_msg

# ElGamal decryption
def asymmetric_decrypt(encrypted_msg, shared_secret_inverse):
    decrypted_msg = []
    for char_code in encrypted_msg:
        decrypted_msg.append(chr(int(char_code / shared_secret_inverse)))

    return decrypted_msg




# Extended Euclidean algorithm for modular inverse
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


if __name__ == "__main__":
    print("===========================================================================")
    print("DIFFIE ELGAMAL CRYPTO SYSTEM")
    print("===========================================================================")
    security_parameter=int(input("Security Parameter [Key Size n][1^n]: ")) 
    
    prime = generate_n_bit_prime(security_parameter)
    primitive_root = find_primitive_root(prime)
    p=prime
    g=primitive_root
    p_subscript = ''.join(chr(0x2080 + int(d)) for d in str(prime))  # Convert digits to subscript Unicode characters
    
    print("\n---------------------------------------------------------------------------")
    print(f"Randomly Genrating Prime of {security_parameter} Bits [q]: ",prime)
    print("Primitive Root of Generated Prime  : ",primitive_root)
    print(f"\nGroup [G]: Z*{p_subscript}")
    print(f"Generator of Group [g]: {g}")
    print("---------------------------------------------------------------------------")

    # Perform Diffie-Hellman key exchange
    shared_secret,shared_secret_inverse = diffie_hellman(prime, primitive_root)
    print("\n===========================================================================")

    
    otp_alice = hashlib.sha256(str(shared_secret).encode()).hexdigest()[:9]
    otp_bob = hashlib.sha256(str(shared_secret).encode()).hexdigest()[:9]
    print("\nAlice OTP: ",otp_alice)
    print("Bob OTP: ",otp_bob)
    message=input("\nEnter Message to Encrypt and Decrypt: ")

    encrypted_message = asymmetric_encrypt(message, shared_secret)
    decrypted_message = asymmetric_decrypt(encrypted_message, shared_secret_inverse)
    decrypted_message_str = ''.join(decrypted_message)
    encrypted_text = ''.join(chr(num % 256) for num in encrypted_message)
    print("\nEncrypted Message:", encrypted_message)
    print("\nEncrypted Message (Text Format):", encrypted_text)
    print("\nDecrypted Message:", decrypted_message_str)
    print("===========================================================================")
    