
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	if argv.length > 0 
		puts bitcoin_privkey_to_pubkey argv[0]
	else
		printf "Usage : ruby %s <privatekey WIF>\n", __FILE__
	end	
end

main ARGV
