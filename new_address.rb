
require 'rbtcrypto.rb'

#-------------
def main( argv )
	
	privkey = bitcoin_generate_new_private_key()
	pubkey  = bitcoin_priv_to_pub( privkey )
	
	puts "Private key : #{privkey}"
	puts "Public  key : #{pubkey}"

end

main ARGV
