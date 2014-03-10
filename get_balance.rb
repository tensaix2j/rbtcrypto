
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	if argv.length > 0 
	
		if bitcoin_verify_pubkey( argv[0] )  == true
			puts get_balance( argv[0] )
		else
			puts "Invalid public key #{argv[0]}"
		end
	else
		printf "Usage : ruby %s <public key>\n", __FILE__
	end	
end

main ARGV