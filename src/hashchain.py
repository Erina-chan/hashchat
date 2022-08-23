from Crypto.Hash import SHA256

def message_x(seed, counter, msg):
	"""
	Generates an X code related to the message msg.
	In this function is used the SHA256 to generate X. 
	However, any Pseudorandom Function (PRF) could be used. 
    
    Args:
        seed: shared secret between this user and
        counter: messages number counter
        msg: message sent/received

    Returns:
    	The message's X code
	"""
	x = seed +bytes(counter) + msg
	return SHA256.new(x).hexdigest()

def verify_prev_hash(new_block, last_block):
	"""
	Verifies if the new_block's prev_hash is correct.

	Args:
		new_block: the block received before insert in hashchain.
		last_block: the last block inserted in hashchain.

	Returns:
		Boolean value of validation result.
	"""
	return new_block["prev_hash"] == last_block["prev_hash"]
