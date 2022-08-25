from Crypto.Hash import SHA256
from src.block import *

class AtD:
	def __init__(self, position, blocks):
		self.position = position
		for block in blocks:
			self.sequency.append(block.hash())

	def hash(self):
		for value in sequency:
			x = x + value
		x_as_bytes = str.encode(x)
		return SHA256.new(x).hexdigest()

	def verify_AtD (new_block):
		