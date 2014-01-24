
require_relative 'rbtcrypto.rb'

#-------------
def main( argv )
	
	keypair = bitcoin_generate_key_pair() 
	
	puts "Private key : #{ keypair[0] }"
	puts "Public  key : #{ keypair[1] }"

end

main ARGV
