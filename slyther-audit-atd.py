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
MY_PUBLIC_KEY_PATH = "data/atd/my_public.pem"
CONTACT_PUBLIC_KEY_PATH = "data/atd/contact_public.pem"


def print_banner():
    """Prints the entry banner."""
    print_green("/////////////////////")
    print_green("// s l y t h e r ////")
    print_green("/ AtD a u d i t o r /")
    print_green("/////////////////////")

def load_hashchain():
    """
    Loads the hashchain dictionary.
    
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
    hasher = SHA256.new(block)
    verifier.verify(hasher, signature)

def verify_atd(blocks, atd):
    """
    Verifies a AtD, returning True of all blocks are in AtD.

    Args:
        blocks: The blocks = [{prev_hash, message_x}] list.
        atd: The AtD to verify blocks list

    Return:
        Valid: Boolean.
    """
    seq_list = atd.sequency.copy()
    for blo in blocks:
        this_block = block(blo["prev_hash"], blo["message_x"])
        if this_block.hash() in seq_list:
            seq_list.remove(this_block.hash())
        else:
            return False
    if len(seq_list) == 0:
        return True
    return False

def search_atd(after_blocks):
    for index, block in enumerate(after_blocks):
        try:
            atd = AtD(block["collision_start"], [])
            atd.sequency = block["sequency"]
            return index
        except:
            continue
    return False

def test_collision(first_collision_msg, seed, atd, collision_list):
    seq_list = atd.sequency.copy()
    prev_block = block(collision_list[0]["prev_hash"], collision_list[0]["message_x"])
    seq_list.remove(prev_block.hash())
    for index, blo in enumerate(collision_list[1:-1]):
        now_block = block(blo["prev_hash"], blo["message_x"])
        if now_block.prev_hash == prev_block.hash():
            seq_list.remove(now_block.hash())
            prev_block = now_block
        else:
            breakpoint()
            msg_x = message_x(seed, atd.position, first_collision_msg)
            prev_block = block(collision_list[0]["prev_hash"], collision_list[0]["message_x"])
            if now_block.prev_hash != prev_block.hash() or now_block.message_x != msg_x:
                print("May happened a change in the records.")
                sys.exit()
            seq_list.remove(now_block.hash())
            prev_block = now_block
            counter = atd.position + 1
            for j, element in enumerate(collision_list[index+1:-1]):
                try:
                    message = input("Next message content: ").encode()
                    msg_x = message_x(seed, counter, message)
                    now_block = block(element["prev_hash"], element["message_x"])
                    if now_block.prev_hash != prev_block.hash() or now_block.message_x != msg_x:
                        print("May happened a change in the records.")
                        sys.exit()
                    seq_list.remove(now_block.hash())
                    prev_block = now_block
                    counter = atd.position + 1
                except KeyboardInterrupt:
                    if confirm("\nWould you like to conclude the audit? (Y/n) "):
                        for rest in collision_list[j:-1]:
                            now_block = block(rest["prev_hash"], rest["message_x"])
                            if now_block.prev_hash != prev_block.hash():
                                print("May happened a change in the records.")
                                sys.exit()
                            seq_list.remove(now_block.hash())
                            prev_block = now_block
                        break
            break
    if len(seq_list) < 0:
        print("May happened a change in the records.")
        sys.exit()

if __name__ == "__main__":
    print_banner()
    chain = load_hashchain()
    my_public_key, contact_public_key = load_keys()

    print("Let's start the audit!")
    # Verify signatures
    try:
        my_int = chain["my_last_sign_position"]
        my_last_block = block(chain["hashchain"][my_int-1]["prev_hash"], chain["hashchain"][my_int-1]["message_x"])
        in_file = open("data/atd/my_last_sign.txt", "rb") 
        my_sign = in_file.read() 
        in_file.close()
        verify_sign(str.encode(my_last_block.hash()), my_sign, my_public_key)
    except ValueError as e:
        print_red("  Error verifing: invalid first signatures.")
        print(e)
        sys.exit()

    try:
        contact_int = chain["contact_last_sign_position"]
        contact_last_block = block(chain["hashchain"][contact_int-1]["prev_hash"], chain["hashchain"][contact_int-1]["message_x"])
        in_file = open("data/atd/contact_last_sign.txt", "rb") 
        contact_sign = in_file.read() 
        in_file.close()
        verify_sign(str.encode(contact_last_block.hash()), contact_sign, contact_public_key)
    except ValueError as e:
        print_red("  Error verifing: invalid second signatures.")
        print(e)
        sys.exit()

    seed_file = open("data/atd/seed.txt", "rb") 
    seed = seed_file.read() 
    seed_file.close()

    print("This chain last signatures are valid.")
    print("From what message do you want to start the audit?")
    n_start = int(input("Message position number: "))
    message = input("Message content: ").encode()

    if n_start == 1:
        msg_x = message_x(seed, 1, message)
        if chain["hashchain"][0]["message_x"] != msg_x:
            print("May happened a change in the records.")
            sys.exit()
        n_atd1 = -1
    else:
        try:
            prev_block = AtD(chain["hashchain"][n_start-2]["collision_start"],[])
            prev_block.sequency = chain["hashchain"][n_start-2]["sequency"]
            if chain["hashchain"][n_start-1]["prev_hash"] != prev_block.hash():
                print("May happened a change in the records.")
                sys.exit()
            n_atd1 = -1
        except:
            prev_block = block(chain["hashchain"][n_start-2]["prev_hash"], chain["hashchain"][n_start-2]["message_x"])
            if chain["hashchain"][n_start-1]["prev_hash"] == prev_block.hash() and chain["hashchain"][n_start-1]["message_x"] == message_x(seed, n_start, message):
                n_atd1 = -1
            else:
                n_atd1 = search_atd(chain["hashchain"][n_start:-1])
                if type(n_atd1) is bool:
                    print("May happened a change in the records.")
                    sys.exit()
                first_atd = AtD(chain["hashchain"][n_start + n_atd1]["collision_start"], [])
                first_atd.sequency = chain["hashchain"][n_start + n_atd1]["sequency"]
                test_collision(message, seed, first_atd, chain["hashchain"][first_atd.position-2:n_start + n_atd1])
                found_atd = AtD(chain["hashchain"][n_start + n_atd1 + 1]["collision_start"], [])
                found_atd.sequency = chain["hashchain"][n_start + n_atd1 + 1]["sequency"]
                atd_second =  verify_atd(chain["hashchain"][found_atd.position-2:n_start + n_atd1], found_atd)
                if not atd_second:
                    print("May happened a change in the records.")
                    sys.exit()
    
    if n_atd1 < 0:
        prev_block = block(chain["hashchain"][n_start-1]["prev_hash"], chain["hashchain"][n_start-1]["message_x"])
        counter = n_start+1
    else:
        prev_block = found_atd
        counter = n_start+n_atd1+2

    n = 0
    while n <= len(chain["hashchain"][counter-1:-1]):
        now_block = block(chain["hashchain"][counter-1+n]["prev_hash"], chain["hashchain"][counter-1+n]["message_x"])
        try:
            message = input("Next message content: ").encode()
            msg_x = message_x(seed, counter+n, message)
            if isinstance(prev_block, AtD):
                if now_block.prev_hash != prev_block.hash() or now_block.message_x != msg_x:
                    print("May happened a change in the records.")
                    sys.exit()
                prev_block = now_block
                n = n + 1
            else:
                if now_block.prev_hash == prev_block.hash() and now_block.message_x == msg_x:
                    prev_block = now_block
                    n = n + 1
                else: 
                    collision = search_atd(chain["hashchain"][counter+n:-1])
                    if type(collision) is bool:
                        print("May happened a change in the records.")
                        sys.exit()
                    my_atd = AtD(chain["hashchain"][counter + n + collision]["collision_start"], [])
                    my_atd.sequency = chain["hashchain"][counter + n + collision]["sequency"]
                    test_collision(message, seed, my_atd, chain["hashchain"][my_atd.position-2:counter+n+collision])
                    
                    found_atd = AtD(chain["hashchain"][counter + n + collision + 1]["collision_start"], [])
                    found_atd.sequency = chain["hashchain"][counter + n + collision + 1]["sequency"]
                    atd_second =  verify_atd(chain["hashchain"][found_atd.position-2:counter + n + collision], found_atd)
                    if not atd_second:
                        print("May happened a change in the records.")
                        sys.exit()
                    prev_block = found_atd
                    n = n + collision + 3

        except KeyboardInterrupt:
            if confirm("\nWould you like to conclude the audit? (Y/n) "):
                ending = 0
                while ending <= len(chain["hashchain"][counter+n-1:-1]):
                    now_block = block(chain["hashchain"][counter-1+n+ending]["prev_hash"], chain["hashchain"][counter-1+n+ending]["message_x"])
                    if isinstance(prev_block, AtD):
                        if now_block.prev_hash != prev_block.hash():
                            print("May happened a change in the records.")
                            sys.exit()
                        prev_block = now_block
                        ending = ending + 1
                    else:
                        if now_block.prev_hash == prev_block.hash():
                            prev_block = now_block
                            ending = ending + 1
                        else:
                            colli = search_atd(chain["hashchain"][counter+n+ending:-1])
                            if type(colli) is bool:
                                print("May happened a change in the records.")
                                sys.exit()
                            found_atd = AtD(chain["hashchain"][counter + n + ending + colli]["collision_start"], [])
                            found_atd.sequency = chain["hashchain"][counter + n + ending + colli]["sequency"]
                            atd_first =  verify_atd(chain["hashchain"][found_atd.position-2:counter + n + ending + colli], found_atd)
                            if not atd_first:
                                print("May happened a change in the records.")
                                sys.exit()
                            found_atd = AtD(chain["hashchain"][counter + n + ending + colli + 1]["collision_start"], [])
                            found_atd.sequency = chain["hashchain"][counter + n + ending + colli + 1]["sequency"]
                            atd_second =  verify_atd(chain["hashchain"][found_atd.position-2:counter + n + ending + colli], found_atd)
                            if not atd_second:
                                print("May happened a change in the records.")
                                sys.exit()
                            found_atd.sequency = chain["hashchain"][counter + n + ending + colli + 1]["sequency"]
                            prev_block = found_atd
                            ending = ending + colli + 3
                break             
    print("All records are correct.")