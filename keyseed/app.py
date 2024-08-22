import sys
import hashlib
from mnemonic import Mnemonic
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


# Mapping of number of words to mnemonic strength
WORD_TO_STRENGTH = {
    12: 128,
    15: 160,
    18: 192,
    21: 224,
    24: 256
}

# Set seed words lang
mnemo = Mnemonic("english")

class SeededRandom:
    def __init__(self, seed):
        self.seed = seed
        self.index = 0

    def read(self, n):
        result = b''
        while len(result) < n:
            data = self.seed + self.index.to_bytes(4, 'big')
            result += hashlib.sha256(data).digest()
            self.index += 1
        return result[:n]


def generate_rsa_key(bits, mnemonic_strength):

    mnemonic_phrase = mnemo.generate(strength=mnemonic_strength)

    seed = mnemo.to_seed(mnemonic_phrase, passphrase="")

    seeded_rng = SeededRandom(seed)

    rsa_key = RSA.generate(bits, randfunc=seeded_rng.read)

    private_key_pem = rsa_key.export_key(format='PEM', pkcs=8).decode('utf-8').strip()

    public_key_pem = rsa_key.publickey().export_key().decode('utf-8').strip()

    return private_key_pem, public_key_pem, mnemonic_phrase

def generate_ed25519_key(mnemonic_strength):
    mnemonic_phrase = mnemo.generate(strength=mnemonic_strength)

    seed = mnemo.to_seed(mnemonic_phrase, passphrase="")

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8').strip()

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8').strip()


    return private_key_pem, public_key_pem, mnemonic_phrase

def generate_mnemonic_and_keys():
    num_words = int(input("Enter number of words for mnemonic seed (12, 15, 18, 21, 24): "))
    if num_words not in WORD_TO_STRENGTH:
        raise ValueError("Invalid number of words. Valid options are 12, 15, 18, 21, 24.")

    mnemonic_strength = WORD_TO_STRENGTH[num_words]

    encryption_algorithm = input("Enter encryption algorithm (rsa, eddsa): ").lower()

    if encryption_algorithm == "rsa":
        bits = int(input("Enter number of bits for RSA (2048, 3072, 4096): "))
        private_key_pem, public_key_pem, mnemonic_phrase = generate_rsa_key(bits, mnemonic_strength)

    elif encryption_algorithm == "eddsa":
        private_key_pem, public_key_pem, mnemonic_phrase = generate_ed25519_key(mnemonic_strength)
    else:
        raise ValueError("Invalid encryption algorithm")

    print("\nPrivate Key:\n", private_key_pem)
    print("Public Key:\n", public_key_pem)
    print("Mnemonic Phrase:", mnemonic_phrase)


def recover_rsa_key(bits, mnemonic_phrase):
    seed = mnemo.to_seed(mnemonic_phrase)

    seeded_rng = SeededRandom(seed)

    rsa_key = RSA.generate(bits, randfunc=seeded_rng.read)

    private_key_pem = rsa_key.export_key(format='PEM', pkcs=8).decode('utf-8')
    public_key_pem = rsa_key.publickey().export_key(format='PEM', pkcs=8).decode('utf-8')

    return  private_key_pem, public_key_pem


def recover_ed25519_key(mnemonic_phrase):
    seed = mnemo.to_seed(mnemonic_phrase)

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_key_pem, public_key_pem


def recover_keys_from_seed():
    mnemonic_phrase = input("Enter your mnemonic phrase: ")
    encryption_algorithm = input("Enter encryption algorithm (rsa, eddsa): ").lower()
    if encryption_algorithm == "rsa":
        bits = int(input("Enter number of bits for RSA (2048, 3072, 4096): "))
        private_key_pem, public_key_pem = recover_rsa_key(bits, mnemonic_phrase)
    elif encryption_algorithm == "eddsa":
        private_key_pem, public_key_pem = recover_ed25519_key(mnemonic_phrase)
    else:
        raise ValueError("Invalid encryption algorithm")

    print("\nPrivate Key:\n", private_key_pem)
    print("Public Key:\n", public_key_pem)

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py [create|recover]")
        sys.exit(1)

    option = sys.argv[1]
    if option == "create":
        generate_mnemonic_and_keys()
    elif option == "recover":
        recover_keys_from_seed()
    else:
        print("Invalid option. Use 'create' to generate new keys or 'recover' to recover keys from seed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
