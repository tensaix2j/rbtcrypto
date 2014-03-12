
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	if argv.length > 0 
	
		if bitcoin_verify_pubkey( argv[0] )  == true
			puts "%d satoshis" % get_balance( argv[0] )
		else
			puts "Invalid public address #{argv[0]}"
		end
	else
		printf "Usage : ruby %s <public address>\n", __FILE__
	end	
end

main ARGV
