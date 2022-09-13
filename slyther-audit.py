#!/usr/bin/env python3
import json
from os.path import exists
from src.ui import *
import src.block
from src.hashchain import message_x
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

CHAIN_PATH = "data/audit/hashchain.json"
MY_PUBLIC_KEY_PATH = "data/audit/my_public.pem"
CONTACT_PUBLIC_KEY_PATH = "data/audit/contact_public.pem"

def print_banner():
    """Prints the entry banner."""
    print_green("/////////////////////")
    print_green("// s l y t h e r ////")
    print_green("//// a u d i t o r //")
    print_green("/////////////////////")

def load_hashchain():
    """
    Loads the hashchain dictionary.
    
    Returns:
        A dictionary of chain, in the format:
        { 
            "seed": <byte>
            "my_last_sign": {   
                    position: <int>,
                    sign: <signature> },
            "contact_last_sign">: {   
                    position: <int>,
                    sign: <signature> },
            "hashchain": {  
                    "block": {  "prev_hash": <string>,
                                "message_x": <string> }
                    xor
                    "atd": {
                                "position": <number>,
                                "sequency": <string[]> }
        }
    """
    try:
        with open(CHAIN_PATH, "rb") as hashchain_file:
            chain = hashchain_file.read()
    except FileNotFoundError:
        print_red("Error: File not found.")
        return {}
    except OSError:
        print_red("Error: Contacts data not accessible.")
        return {}
    return json.loads(chain)

def load_keys():
    """
    Loads and returns keys from default paths.

    Returns:
        A public key Crypto.PublicKey.RSA.RsaKeys.
    """
    try:
        with open(MY_PUBLIC_KEY_PATH, "rb") as public_file:
            my_public = RSA.import_key(public_file.read())

        with open(CONTACT_PUBLIC_KEY_PATH, "rb") as public_file:
            contact_public = RSA.import_key(public_file.read())

    except FileNotFoundError:
        print_red("Error: No keys found.")
        exit()
    except OSError:
        print_red("Error: Keys inaccessible.")
        exit()

    return my_public, contact_public

def verify_sign(block, signature, key):
    """
    Verifies a signature, throwing an error if it is invalid.

    Args:
        block: The block (prev_hash, message_x) signed by the signature.
        signature: The signature produced by sign() to verify.
        key: The opposing key of the Crypto.PublicKey.RSA.RsaKey used to 
            sign the message.

    Raises:
        ValueError: Invalid signature.
    """
    verifier = pkcs1_15.new(key)
    hasher = SHA256.new(message)
    verifier.verify(hasher, signature)


if __name__ == "__main__":
    print_banner()
    chain = load_hashchain()
    my_public_key, contact_public_key = load_keys()

    print("Let's start the audit!")
    # Verify signatures
    try:
        my_int = chain["my_last_sign"]["position"]
        my_last_block = chain["hashchain"][my_int]
        verify(str.encode(my_last_block.hash()), chain["my_last_sign"]["sign"], my_public_key)
    except ValueError as e:
        print_red("    : Error verifing first signatures.")
        print(e)

    try:
        contact_int = chain["contact_last_sign"]["position"]
        contact_last_block = chain["hashchain"][contact_int]
        verify(str.encode(contact_last_block.hash()), chain["contact_last_sign"]["sign"], contact_public_key)
    except ValueError as e:
        print_red("    : Error verifing first signatures.")
        print(e)

    correct = True
    print("This chain last signatures are valid.")
    print("From what message do you want to start the audit?")
    n_start = input("Message position number: ").encode()
    message = input("Message content: ").encode()
    prev_block = chain["hashchain"][n_start-2]
    if chain["hashchain"][n_start-1]["prev_hash"] == prev_block.hash() and 
       chain["hashchain"][n_start-1]["message_x"] == message_x(seed, n_start, message):
        while n_start < len(chain["hashchain"]):
            try:
                message = input("Next message content: ").encode()
                prev_block = chain["hashchain"][n_start-1]
                if chain["hashchain"][n_start]["prev_hash"] != prev_block.hash() or 
                   chain["hashchain"][n_start]["message_x"] != message_x(seed, n_start+1, message):
                    print("May happened a change in the records.")
                    correct = False
                    break
                n_start = n_start + 1
            except KeyboardInterrupt:
                if confirm("\nWould you like to conclude the audit? (Y/n) "):
                    # verifica a conexão do último bloco com o próximo
                    prev_block = chain["hashchain"][n_start-1]
                    if chain["hashchain"][n_start]["prev_hash"] != prev_block.hash():
                        print("May happened a change in the records.")
                        correct = False
                    break 
        if correct:
            print("All records are correct.")
    else:
        print("May happened a change in the records.")