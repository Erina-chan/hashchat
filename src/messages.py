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