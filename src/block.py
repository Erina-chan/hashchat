from Crypto.Hash import SHA256

class block:
	def __init__(self, prev_hash, message_x):
		self.prev_hash = prev_hash
		self.message_x = message_x

	def hash():
		x = self.prev_hash + self.message_x
		return SHA256.new(x).hexdigest()