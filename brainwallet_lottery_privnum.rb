
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	
	if argv.length > 0 
		keypair = bitcoin_generate_key_pair_by_privnum( argv[0].to_i )

		puts "Private key    : #{ keypair[0] }"
		puts "Public address : #{ keypair[1] }"
		
		res = get_account_status( keypair[1] )

		puts "Received      : %.8f BTC" % (res["total_received"].to_f / 100000000)
		puts "Sent          : %.8f BTC" % (res["total_sent"].to_f / 100000000)
		puts "Final Balance : %.8f BTC" % (res["final_balance"].to_f / 100000000)


		
	else
		printf "Usage : ruby %s <passphrase>\n", __FILE__
	end

end

main ARGV
