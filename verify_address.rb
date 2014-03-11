
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	if argv.length > 0 
		
		if argv[0][0].chr == "1"
			printf "%s\n", bitcoin_verify_pubkey( argv[0]  ) ? "Valid" : "Invalid"
		else
			printf "%s\n", bitcoin_verify_privkey( argv[0] ) ? "Valid" : "Invalid"
 		end

	else
		printf "Usage : ruby %s <private key | public address>\n", __FILE__
	end	
end

main ARGV
