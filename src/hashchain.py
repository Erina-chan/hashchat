from Crypto.Hash import SHA256

def message_x(seed, counter, msg):
	"""
	Generates an X code related to the message msg.
	In this function is used the SHA256 to generate X. 
	However, any Pseudorandom Function (PRF) could be used. 
    
    Args:
        seed: shared secret between this user and
        counter: messages number counter
        msg; message sent/received

    Returns:
    	The message's X code
	"""
	x = seed +bytes(counter) + msg
	return SHA256.new(x)


def generate_block(msg):
	"""
	...
	"""
	# get seed
	
	# get couter

	# generate x

	# get chian last_block 
	
	return prev_hash, mgs_x

def verify_prev_hash(new_block):
	"""
	Verifies if the new_block's prev_hash is correct.

	Args:
		new_block

	Returns:
		Boolean value of validation result.
	"""