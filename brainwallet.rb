
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	
	if argv.length > 0 
		keypair = bitcoin_generate_key_pair_by_passphrase( argv[0] )

		puts "Private key    : #{ keypair[0] }"
		puts "Public address : #{ keypair[1] }"
	else
		printf "Usage : ruby %s <passphrase>\n", __FILE__
	end

end

main ARGV
