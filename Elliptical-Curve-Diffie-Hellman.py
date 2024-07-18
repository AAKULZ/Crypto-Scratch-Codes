import hashlib
import os
import random

class EllipticCurve:
    def __init__(self, p=None, a=None, b=None, G=None):
        if p is None:
            self.p = self.generate_prime()
        else:
            self.p = p
        if a is None:
            self.a = random.randint(0, self.p - 1)
        else:
            self.a = a
        if b is None:
            self.b = random.randint(0, self.p - 1)
        else:
            self.b = b
        if G is None:
            self.G = self.generate_base_point()
        else:
            self.G = G

    def generate_prime(self):
        """Generate a large prime number."""
        # This is a simple method for demonstration purpose only
        # In practice, better prime generation methods should be used
        return 2**256 - 2**32 - 977

    def generate_base_point(self):
        """Generate a base point on the elliptic curve."""
        # This is a simple method for demonstration purpose only
        # In practice, better base point generation methods should be used
        x = random.randint(1, self.p - 1)
        y = random.randint(1, self.p - 1)
        return x, y

class ECC:
    def __init__(self, curve):
        self.curve = curve

    def modinv(self, a, n):
        """Compute the modular inverse."""
        return pow(a, -1, n)

    def point_add(self, p1, p2):
        """Add two points on the elliptic curve."""
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and y1 != y2:
            return None
        if p1 != p2:
            s = ((y2 - y1) * self.modinv(x2 - x1, self.curve.p)) % self.curve.p
        else:
            s = ((3 * x1 * x1 + self.curve.a) * self.modinv(2 * y1, self.curve.p)) % self.curve.p
        x3 = (s * s - x1 - x2) % self.curve.p
        y3 = (s * (x1 - x3) - y1) % self.curve.p
        return (x3, y3)

    def point_multiply(self, k, p):
        """Multiply a point on the elliptic curve by a scalar."""
        result = None
        while k > 0:
            if k & 1:
                result = self.point_add(result, p)
            k >>= 1
            p = self.point_add(p, p)
        return result

    def sha256(self, data):
        """Compute SHA-256 hash."""
        return hashlib.sha256(data).digest()

    def generate_keypair(self):
        """Generate a random ECC key pair."""
        private_key = int.from_bytes(os.urandom(32), byteorder='big')
        public_key = self.point_multiply(private_key, self.curve.G)
        return private_key, public_key

    def derive_shared_secret(self, private_key, public_key):
        """Derive the shared secret."""
        shared_secret = self.point_multiply(private_key, public_key)
        return shared_secret[0]

    def encrypt_text(self, plaintext, shared_secret):
        """Encrypt the plaintext using XOR with SHA-256 of the shared secret."""
        key = self.sha256(shared_secret.to_bytes(32, byteorder='big'))
        ciphertext = bytearray()
        for i in range(len(plaintext)):
            ciphertext.append(plaintext[i] ^ key[i % len(key)])
        return bytes(ciphertext)

    def decrypt_text(self, ciphertext, shared_secret):
        """Decrypt the ciphertext using XOR with SHA-256 of the shared secret."""
        key = self.sha256(shared_secret.to_bytes(32, byteorder='big'))
        plaintext = bytearray()
        for i in range(len(ciphertext)):
            plaintext.append(ciphertext[i] ^ key[i % len(key)])
        return bytes(plaintext)

# Example usage
if __name__ == "__main__":
    print("===========================================================================")
    print("Elliptic Curve Diffie Hellman Key Exchange and Encryption-Decryption")
    print("===========================================================================")

    # Generate curve and initialize ECC object
    curve = EllipticCurve()
    ecc = ECC(curve)

    print("\n---------------------------------------------------------------------------")
    print("Alice Keys ")
    print("---------------------------------------------------------------------------")
    alice_private_key, alice_public_key = ecc.generate_keypair()
    print("Private Key [x]:", alice_private_key)
    print("Public Key [h1 = x * base_point]:", alice_public_key)
    print("---------------------------------------------------------------------------")

    print("\n---------------------------------------------------------------------------")
    print("Bob Keys ")
    print("---------------------------------------------------------------------------")
    bob_private_key, bob_public_key = ecc.generate_keypair()
    print("Private Key [x]:", bob_private_key)
    print("Public Key [h1 = x * base_point]:", bob_public_key)
    print("---------------------------------------------------------------------------")

    # Exchange public keys
    shared_secret_alice = ecc.derive_shared_secret(alice_private_key, bob_public_key)
    shared_secret_bob = ecc.derive_shared_secret(bob_private_key, alice_public_key)

    # Ensure both shared secrets match
    assert shared_secret_alice == shared_secret_bob

    # Print shared secret
    print("Shared Secret:", shared_secret_alice)

    # Encrypt and decrypt
    print("---------------------------------------------------------------------------")
    plaintext = input("Enter the plaintext to encrypt: ").encode('utf-8')
    ciphertext = ecc.encrypt_text(plaintext, shared_secret_alice)
    decrypted_text = ecc.decrypt_text(ciphertext, shared_secret_alice)
    
    print("\nEncrypted Message:", ciphertext)
    print("\nDecrypted Message:", decrypted_text)
    print("===========================================================================")
