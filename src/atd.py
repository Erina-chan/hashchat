from Crypto.Hash import SHA256
from src.block import *

class AtD:
	def __init__(self, position, blocks):
		self.position = position
		self.sequency = []
		for block in blocks:
			self.sequency.append(block.hash())

	def hash(self):
		x = ""
		for value in self.sequency:
			x = x + value
		x_as_bytes = str.encode(x)
		return SHA256.new(x_as_bytes).hexdigest()