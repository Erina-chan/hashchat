#!/usr/bin/env python3
import json
import sys
import base64
from os.path import exists
from src.ui import *
from src.atd import *
from src.block import *
from src.hashchain import message_x
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA

CHAIN_DIR = "data/atd/"
CHAIN_PATH = "data/atd/hashchain.json"
SEED_PATH = "data/atd/seed.txt"
MY_PRIVATE_KEY_PATH = "data/atd/my_private.pem"
MY_PUBLIC_KEY_PATH = "data/atd/my_public.pem"
CONTACT_PRIVATE_KEY_PATH = "data/atd/contact_private.pem"
CONTACT_PUBLIC_KEY_PATH = "data/atd/contact_public.pem"

def print_banner():
    """Prints the entry banner."""
    print_green("/////////////////////")
    print_green("// s l y t h e r ////")
    print_green("//// c h a t + AtD //")
    print_green("/////////////////////")

def save_hashchain(chain):
    """
    Save the hashchain dictionary.
    
    Returns:
        A dictionary of chain, in the format:
        { 
            "my_last_sign_position": <int>,
            "contact_last_sign_position": <int>,
            "hashchain": {  
                    "block": {  "prev_hash": <string>,
                                "message_x": <string> }
                    xor
                    "atd": {
                                "position": <number>,
                                "sequency": <string[]> }
        }
    """
    chain_string = json.dumps(chain)
    chain_bytes = chain_string.encode()
    try:
        with open(CHAIN_PATH, "wb") as contacts_file:
            contacts_file.write(chain_bytes)
    except OSError:
        if not exists(CHAIN_DIR):
            makedirs(CHAIN_DIR)
            with open(CHAIN_PATH, "wb") as contacts_file:
                contacts_file.write(chain_bytes)
        else:
            print_red("Error: Contacts file not accessible.")

def load_keys():
    """
    Loads and returns keys from default paths.
    
    Args:
        password: The password to decrypt the private key file.

    Returns:
        A tuple of (public key, private key), where both keys are 
        Crypto.PublicKey.RSA.RsaKeys.
    """
    my_password = getpass_handled("My password: ")
    contact_password = getpass_handled("Contact password: ")
    try:
        with open(MY_PRIVATE_KEY_PATH, "rb") as private_file:
            my_private = RSA.import_key(private_file.read(), passphrase=my_password)

        with open(MY_PUBLIC_KEY_PATH, "rb") as public_file:
            my_public = RSA.import_key(public_file.read())

        with open(CONTACT_PRIVATE_KEY_PATH, "rb") as private_file:
            contact_private = RSA.import_key(private_file.read(), passphrase=contact_password)

        with open(CONTACT_PUBLIC_KEY_PATH, "rb") as public_file:
            contact_public = RSA.import_key(public_file.read())

    except FileNotFoundError:
        print_red("Error: No keys found.")
        exit()
    except OSError:
        print_red("Error: Keys inaccessible.")
        exit()

    return my_private, my_public, contact_private, contact_public

def sign(message, key):
    """
    Returns a signature of a message given an RSA key.

    Args:
        message: The message (in bytes) to sign.
        key: The Crypto.PublicKey.RSA.RsaKey with which to sign the message.

    Returns:
        A signature (in bytes) of the message.
    """
    hasher = SHA256.new()
    hasher.update(message)
    signer = pkcs1_15.new(key)
    return signer.sign(hasher)

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
    hasher = SHA256.new(block)
    verifier.verify(hasher, signature)


if __name__ == "__main__":
    print_banner()
    my_private_key, my_public_key, contact_private_key, contact_public_key = load_keys()

    seed_file = open(SEED_PATH, "rb") 
    seed = seed_file.read() 
    seed_file.close()

    messages = []
    hashchain = []
    collision = False

    print("Let's start the chat!")
    message = input("Message content: ").encode()
    sender = confirm("You are the sender? (Y/n) ")
    new_message = { "position": 1, "recieved": sender, "contents": message.decode()}
    messages.append(new_message)

    new_block = block("0000000000000000000000000000000000000000000000000000000000000000", message_x(seed, 1, message))
    new_block_dic = {"prev_hash": "0000000000000000000000000000000000000000000000000000000000000000", "message_x": message_x(seed, 1, message)}
    hashchain.append(new_block_dic)

    if sender:
        my_sign = sign(str.encode(new_block.hash()), my_private_key)
        f = open("data/atd/my_last_sign.txt", "wb")
        f.write(my_sign)
        f.close()
        my_last_sign_position = 1
        contact_last_sign_position = 0
    else:
        contact_sign = sign(str.encode(new_block.hash()), contact_private_key)
        f = open("data/atd/contact_last_sign.txt", "wb")
        f.write(contact_sign)
        f.close()
        my_last_sign_position = 0
        contact_last_sign_position = 1

    while True:
        try:
            message = input("Next message content: ").encode()
            sender = confirm("You are the sender? (Y/n) ")
            position = int(input("This message's position is number: "))
            new_message = { "position": position, "recieved": sender, "contents": message.decode()}
            messages.append(new_message)

            prev_block = block(hashchain[position-2]["prev_hash"], hashchain[position-2]["message_x"])
            new_block = block(prev_block.hash(), message_x(seed, position, message))
            new_block_dic = {"prev_hash": prev_block.hash(), "message_x": message_x(seed, position, message)}
            hashchain.append(new_block_dic)

            if sender:
                my_sign = sign(str.encode(new_block.hash()), my_private_key)
                f = open("data/atd/my_last_sign.txt", "wb")
                f.write(my_sign)
                f.close()
                my_last_sign_position = position

            else:
                contact_sign = sign(str.encode(new_block.hash()), contact_private_key)
                f = open("data/atd/contact_last_sign.txt", "wb")
                f.write(contact_sign)
                f.close()
                contact_last_sign_position = position

            if position < len(hashchain) or collision:
                if not collision:
                    collision_start = position
                    my_blocks = [block(hashchain[position-2]["prev_hash"], hashchain[position-2]["message_x"])]
                    contact_block = [block(hashchain[position-2]["prev_hash"], hashchain[position-2]["message_x"])]
                    contact_block.append(new_block)
                    contact_num = len(contact_block)
                    while position-1 < len(hashchain):
                        my_blocks.append(block(hashchain[position-1]["prev_hash"], hashchain[position-1]["message_x"]))
                        contact_block.append(block(hashchain[position-1]["prev_hash"], hashchain[position-1]["message_x"]))
                        position = position + 1
                    collision = True
                else:
                    my_blocks.append(new_block)
                    contact_block.insert(contact_num, new_block)
                    contact_num = contact_num + 1
                if confirm("\nColission detected. Do you want to finish the collision (Y/n) "):
                    # generate atd block
                    my_collision_block = AtD(collision_start, my_blocks)
                    my_atd_dic = {"collision_start": collision_start, "sequency": my_collision_block.sequency}
                    hashchain.append(my_atd_dic)
                    my_last_sign_position = len(hashchain)
                    my_sign = sign(str.encode(my_collision_block.hash()), my_private_key)
                    f = open("data/atd/my_last_sign.txt", "wb")
                    f.write(my_sign)
                    f.close()

                    contact_collision_block = AtD(collision_start, contact_block)
                    contact_atd_dic = {"collision_start": collision_start, "sequency": contact_collision_block.sequency}
                    hashchain.append(contact_atd_dic)
                    contact_last_sign_position = len(hashchain)
                    contact_sign = sign(str.encode(contact_collision_block.hash()), contact_private_key)
                    f = open("data/atd/contact_last_sign.txt", "wb")
                    f.write(contact_sign)
                    f.close()
                    collision = False

                    message = input("My next message after collision finish: ").encode()
                    sender = True
                    position = len(hashchain)
                    new_message = {"position": position, "recieved": sender, "contents": message.decode()}
                    messages.append(new_message)

                    prev_atd_hash = contact_collision_block.hash()
                    new_block = block(prev_atd_hash, message_x(seed, position, message))
                    new_block_dic = {"prev_hash": prev_atd_hash, "message_x": message_x(seed, position, message)}
                    hashchain.append(new_block_dic)
                    
                    my_sign = sign(str.encode(new_block.hash()), my_private_key)
                    f = open("data/atd/my_last_sign.txt", "wb")
                    f.write(my_sign)
                    f.close()
                    my_last_sign_position = position

        except KeyboardInterrupt:
            if confirm("\nDo you like to finish atd-script? (Y/n) "):
               break
               
    # Save the chain in the json file 
    chain = {"my_last_sign_position": my_last_sign_position, "contact_last_sign_position": contact_last_sign_position, "hashchain": hashchain}
    save_hashchain(chain)