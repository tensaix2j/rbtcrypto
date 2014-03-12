require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	if argv.length > 0 
		puts  deserialize_transaction( argv[0] )

	else
		printf "Usage : ruby %s <transaction hexstring>\n", __FILE__
	end	
end

main ARGV
