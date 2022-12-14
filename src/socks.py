import socket
import struct
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from src.fingerprints import verify_fingerprint

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

from src.hashchain import message_x
from src.block import *


PORT = 5300


def transmit(contact, message, public, private, private_ecdh, public_ecdh, check_fingerprint=True):
    """
    Sends a message to the provided contact.

    Args:
        contact: The contact information of the recipient in the format:
            { "name": <name>, "ip": <ip>, "fingerprint": <fingerprint>, "messages": <messages>}
            For more detail, see load_contacts() in src/contacts.py.
        message: The message (in bytes) to send.
        public: The user's public RSA key.
        private: The user's private RSA key.
        private_ecdh: The user's private ECDH key.
        public_ecdh: The user's public ECDH key.
        fingerprint_verify: Whether or not to throw a warning when a client's public key
            doesn't match their fingerprint.

    Raises:
        socket.error: Client server not accessible.
        socket.timeout: Connection timed out.
    """
    contact_addr = (contact["ip"], PORT)

    with socket.create_connection(contact_addr, 15) as sock:
        # Exchanging public keys
        send(sock, public.export_key())
        client_public = RSA.import_key(receive(sock))

        # Exchanging public ECDH keys
        send(sock, public_ecdh.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
        client_public_ecdh = load_pem_public_key(data=receive(sock)) 

        # Verify client key against fingerprint
        if check_fingerprint and contact["fingerprint"]:
            assert(verify_fingerprint(client_public, contact["fingerprint"]))

        # Creating and sending session key
        session = get_random_bytes(16)
        send_session(sock, session, client_public, private)        

        # Sending message
        send_aes(sock, message, session, private)

        # Sending block with this signature
        seed = exchange_ecdh(private_ecdh, client_public_ecdh)
        x = message_x(seed, contact["counter"]+1, message)
        if contact["counter"] == 0:
            my_block = block("0000000000000000000000000000000000000000000000000000000000000000", x)
        else: 
            prev_block = block(contact["hashchain"][-1]["prev_hash"], contact["hashchain"][-1]["message_x"])
            my_block = block(prev_block.hash(), x)
        sig = send_block(sock, my_block, session, private)

        return seed, sig


def send(sock, message):
    """
    Prefixes a message with its size and sends it to be received by recvall().
    
    Args:
        sock: The socket from which to send.
        message: The data to send.
    """
    packed = struct.pack("h", len(message)) + message
    sock.sendall(packed)


def receive(sock):
    """
    Receives and returns a message sent from send().

    Args:
        sock: The sock from which to receive.
    """
    # Get the length of the message
    message_len_raw = recvall(sock, 2)
    if not message_len_raw:
        raise socket.error("Connection lost")
    message_len = struct.unpack("=h", message_len_raw)[0]

    # Return the rest of the message
    return recvall(sock, message_len)


def recvall(sock, num_bytes):
    """
    Receives a size-prefixed message from the send() function above.
    Thanks to Adam Rosenfield and Hedde van der Heide for the elegant solution.

    Args:
        sock: The socket to receive from.

    Returns:
        The complete message received by the socket, or None if no data is received.
    """
    received = bytes()
    while len(received) < num_bytes:
        data = sock.recv(num_bytes - len(received))
        if not data:
            return None
        received += data
    
    return received


def encrypt_rsa(message, key):
    """
    Encrypts a message with the provided RSA key.

    Args:
        message: The message (in bytes) to encrypt.
        key: The Crypto.PublicKey.RSA.RsaKey with which to encrypt.

    Returns:
        The encrypted message in bytes.
    """
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)

def decrypt_rsa(message, key):
    """
    Decrypts a message with the provided RSA key.

    Args:
        message: The message (in bytes) to decrypt.
        key: The Crypto.PublicKey.RSA.RsaKey with which to decrypt.

    Returns:
        The decrypted message in bytes.
    """
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(message)


def encrypt_aes(message, key):
    """
    Encrypts a message with the provided AES key.

    Args:
        message: The message (in bytes) to encrypt.
        key: The AES key (in bytes) with which to decrypt.

    Returns:
        The encrypted message in bytes, where the first 16 bytesare the nonce, 
        the second 16 are the tag, and the rest are the ciphertext:

             Nonce          Tag         Ciphertext
        [-----16-----][-----16-----][-------n-------]
    """
    aes_cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message)
    total = bytearray(aes_cipher.nonce)
    total.extend(bytes(tag))
    total.extend(bytes(ciphertext))
    return bytes(total)


def decrypt_aes(message, key):
    """
    Decrypts a message with the provided AES key.

    Args:
        message: The message (in bytes, as formatted by encrypt_aes()) to decrypt.
        key: The AES key (in bytes) with which to decrypt.

    Returns:
        The decrypted message in bytes.
    """
    nonce = message[:16]
    tag = message[16:32]
    ciphertext = message[32:]
    aes_cipher = AES.new(key, AES.MODE_EAX, nonce)
    return aes_cipher.decrypt_and_verify(ciphertext, tag)    


def send_session(sock, session, client_public, private):
    """
    Sends an AES session key over hybrid RSA/AES through a socket.

    Sends the RSA-encrypted session key, then sends the AES-encrypted signature 
    of the key.

    Args:
        sock: The socket connected to the client.
        session: The AES session key (in bytes) to send.
        client_public: The client's public RSA key (as a Crypto.PublicKey.RSA.RsaKey).
        private: The private RSA key of the sender (as a Crypto.PublicKey.RSA.RsaKey).
    """
    encrypted_session = encrypt_rsa(session, client_public)
    signature = sign(session, private)
    encrypted_signature = encrypt_aes(signature, session)
    send(sock, encrypted_session)
    send(sock, encrypted_signature)


def receive_session(sock, client_public, private):
    """
    Receives an AES session key over hybrid RSA/AES through a socket.
    
    For further description see send_session().

    Args:
        sock: The socket connected to the sender.
        client_public: The sender's public RSA key (as a Crypto.PublicKey.RSA.RsaKey).
        private: The private RSA key of the receiver (as a Crypto.PublicKey.RSA.RsaKey).
    """
    encrypted_session = receive(sock)
    session_key = decrypt_rsa(encrypted_session, private)

    encrypted_signature = receive(sock)
    signature = decrypt_aes(encrypted_signature, session_key)
    verify(session_key, signature, client_public)
    
    return session_key


def send_aes(sock, message, session_key, private):
    """
    Encrypts the message with AES and sends it as well as its signature through a socket.

    Args:
        sock: The socket connected to the client.
        message: The message (in bytes) to send.
        client_public: The client's public RSA key (as a Crypto.PublicKey.RSA.RsaKey).
        private: The private RSA key of the sender (as a Crypto.PublicKey.RSA.RsaKey).
    """
    encrypted_message = encrypt_aes(message, session_key)
    signature = sign(message, private)
    encrypted_signature = encrypt_aes(signature, session_key)
    send(sock, encrypted_message)
    send(sock, encrypted_signature)


def receive_aes(sock, client_public, key):
    """
    Decrypts and verifies a message sent through a socket by send_aes().

    Args:
        sock: The socket connected to the sender.
        client_public: The sender's public RSA key (as a Crypto.PublicKey.RSA.RsaKey).
        key: The private RSA key of the receiver (as a Crypto.PublicKey.RSA.RsaKey).
    """
    encrypted_message = receive(sock)
    message = decrypt_aes(encrypted_message, key)

    encrypted_signature = receive(sock)
    signature = decrypt_aes(encrypted_signature, key)
    verify(message, signature, client_public)
    
    return message


def send_block(sock, block, session_key, private):
    signature = sign(str.encode(block.hash()), private)
    encrypted_signature = encrypt_aes(signature, session_key)
    send(sock, str.encode(block.prev_hash))
    send(sock, str.encode(block.message_x))
    send(sock, encrypted_signature)
    return signature


def receive_block(sock, client_public, key):
    message_prev_hash = receive(sock).decode("utf-8")
    message_x = receive(sock).decode("utf-8")
    received_block = block(message_prev_hash, message_x)
    encrypted_signature = receive(sock)
    signature = decrypt_aes(encrypted_signature, key)
    verify(str.encode(received_block.hash()), signature, client_public)
    
    return received_block, signature


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

def verify(message, signature, key):
    """
    Verifies a signature, throwing an error if it is invalid.

    Args:
        message: The plaintext message (in bytes) signed by the signature.
        signature: The signature produced by sign() to verify.
        key: The opposing key of the Crypto.PublicKey.RSA.RsaKey used to 
            sign the message.

    Raises:
        ValueError: Invalid signature.
    """
    verifier = pkcs1_15.new(key)
    hasher = SHA256.new(message)
    verifier.verify(hasher, signature)

def exchange_ecdh(my_private_ecdh_key, peer_ecdh_public_key):
    """
    Generates the ECDH shared key between this user and the peer with whom it is talking.

    Args:
        my_private_ecdh_key: My private ECDH key.
        peer_ecdh_public_key: Peer's public ECDH key.

    Returns:
        A ECDH shared key between this user and the peer. 
    """
    shared_key = my_private_ecdh_key.exchange(ec.ECDH(), peer_ecdh_public_key)

    # Perform key derivation.
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',).derive(shared_key)

    return derived_key