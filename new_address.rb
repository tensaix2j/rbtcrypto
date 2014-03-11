
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	
	keypair = bitcoin_generate_key_pair() 
	
	puts "Private key    : #{ keypair[0] }"
	puts "Public address : #{ keypair[1] }"

end

main ARGV
