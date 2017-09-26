
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	
	if argv.length > 0 
		keypair = bitcoin_generate_key_pair_by_privnum( argv[0].to_i )

		puts "Private key    : #{ keypair[0] }"
		puts "Public address : #{ keypair[1] }"
		
		res = get_account_status( keypair[1] )
		res.keys.each { |key|
			puts "#{key} : #{ res[key] }"
		}

		

		
	else
		printf "Usage : ruby %s <privnum>\n", __FILE__
	end

end

main ARGV
