from Crypto.Hash import SHA256

class AtD:
  def __init__(self, position, blocks):
    self.position = position
    for block in blocks:
    	self.sequency.append(block.hash())

  def hash():
  	for value in sequency:
  		x = x + value
    return SHA256.new(x).hexdigest()