from Crypto.Hash import SHA256

class block:
	def __init__(self, prev_hash, message_x):
		self.prev_hash = prev_hash
		self.message_x = message_x

	def hash(self):
		x = self.prev_hash + self.message_x
		x_as_bytes = str.encode(x)
		return SHA256.new(x_as_bytes).hexdigest()