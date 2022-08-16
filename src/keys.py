from Crypto.PublicKey import RSA
from os import makedirs
from os.path import exists, isfile
from src.ui import *
from time import sleep
from random import random

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, BestAvailableEncryption, Encoding, PrivateFormat, PublicFormat

DIR = "data/keys/"
PUBLIC_PATH = "data/keys/public.pem"
PRIVATE_PATH = "data/keys/private.pem"

PUBLIC_ECDH_PATH = "data/keys/public_ecdh.pem"
PRIVATE_ECDH_PATH = "data/keys/private_ecdh.pem"


def load_keys(password):
    """
    Loads and returns keys from default paths.
    
    Args:
        password: The password to decrypt the private key file.

    Returns:
        A tuple of (public key, private key), where both keys are 
        Crypto.PublicKey.RSA.RsaKeys.
        A tuple of (public key, private key), where both keys are 
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey and
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.
    """
    try:
        with open(PRIVATE_PATH, "rb") as private_file:
            private = RSA.import_key(private_file.read(),
                                              passphrase=password)

        with open(PUBLIC_PATH, "rb") as public_file:
            public = RSA.import_key(public_file.read())

        with open(PRIVATE_ECDH_PATH, "rb") as private_ecdh_file:
            private_ecdh = load_pem_private_key(private_ecdh_file.read(),
                                              password=str.encode(password))

        with open(PUBLIC_ECDH_PATH, "rb") as public_ecdh_file:
            public_ecdh = load_pem_public_key(public_ecdh_file.read())

    except FileNotFoundError:
        print_red("Error: No keys found.")
        exit()
    except OSError:
        print_red("Error: Keys inaccessible.")
        exit()

    return private, public, private_ecdh, public_ecdh


def create_password():
    """Prompts the user to create and confirm a password, and returns the password."""
    password1 = getpass_handled("Password: ")
    password2 = getpass_handled("Confirm password: ")
    while password1 != password2:
        print_red("Your passwords do not match. Please try again:")
        password1 = getpass_handled("Password: ")
        password2 = getpass_handled("Confirm password: ")
    return password1


def create_keys():
    """Generates and returns a Crypto.PublicKey.RSA.RsaKey pair (in a tuple)"""
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    """Generates and returns a EC keys used in ECDH key exchange"""
    private_ecdh_key = ec.generate_private_key(ec.SECP256K1())
    public_ecdh_key = private_ecdh_key.public_key()

    return private_key, public_key, private_ecdh_key, public_ecdh_key


def save_keys(private, public, private_ecdh, public_ecdh, password):
    """
    Saves RSA keys to their default paths.

    Args:
        private: The private RSA key to save.
        public: The public RSA key to save.
        private_ecdh: The private ECDH key to save.
        publick_ecdh; The public ECDH key to save.
        password: The password to encrypt the private key with.
    """
    encrypted_private = private.export_key(passphrase=password,
                                           pkcs=8,
                                           protection="scryptAndAES128-CBC")

    encrypted_private_ecdh = private_ecdh.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=BestAvailableEncryption(password=str.encode(password)))

    if not exists(DIR):
        makedirs(DIR)

    try:
        with open(PRIVATE_PATH, "wb") as private_file:
            private_file.write(encrypted_private)
    except OSError:
        print_red("Error: Private key file inaccessible.")

    try:
        with open(PUBLIC_PATH, "wb") as public_file:
            public_file.write(public.export_key())
    except OSError:
        print_red("Error: Public key file inaccessible.")

    try:
        with open(PRIVATE_ECDH_PATH, "wb") as private_ecdh_file:
            private_ecdh_file.write(encrypted_private_ecdh)
    except OSError:
        print_red("Error: Private key file inaccessible.")

    try:
        with open(PUBLIC_ECDH_PATH, "wb") as public_ecdh_file:
            public_ecdh_file.write(public_ecdh.public_bytes(encoding=Encoding.PEM,
                                           format=PublicFormat.SubjectPublicKeyInfo))
    except OSError:
        print_red("Error: Public key file inaccessible.")


def create_account():
    """
    Walks a user through the process of creating an account.
    
    Gets a user password, creates RSA and ECDH key pairs, and saves them.
    """
    print("Welcome to slyther! Enter a password for your new account to begin...")
    password = create_password()
    private, public, private_ecdh, public_ecdh = create_keys()
    save_keys(private, public, private_ecdh, public_ecdh, password)
    print_green("Account created!\n")


def login():
    """Prompts a user for their password, and returns a tuple of their keys upon success."""
    if not isfile(PRIVATE_PATH) or not isfile(PUBLIC_PATH) or not isfile(PRIVATE_ECDH_PATH) or not isfile(PUBLIC_ECDH_PATH):
        create_account()
    
    print("Please log in...")
    password = getpass_handled("Password: ")
    
    public = ""
    private = ""
    public_ecdh = ""
    private_ecdh = ""

    while True:
        try:
            private, public, private_ecdh, public_ecdh = load_keys(password)
        except ValueError:
            sleep(random() * 2)
            print_red("\nInvalid password. Please try again.")
            password = getpass_handled("Password: ")
            continue
        break

    print_green("Login successful.\n")
    return private, public, private_ecdh, public_ecdh

