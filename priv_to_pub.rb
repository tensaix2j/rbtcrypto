
require_relative 'rbtcrypto.rb'

#-------------
def main( argv )
	if argv.length > 0 
		puts bitcoin_priv_to_pub argv[0]
	else
		printf "Usage ruby %s <privatekey>", __FILE__
	end	
end

main ARGV
