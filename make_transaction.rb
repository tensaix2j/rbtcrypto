
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	
	if argv.length >= 4 
		
		if !bitcoin_verify_pubkey( argv[0] )
			puts "Invalid sender address #{argv[0]}"  	
			return     
		end

		if !bitcoin_verify_pubkey( argv[1] )
			puts "Invalid recipient address #{argv[1]}" 
			return   
		end
		
		if !bitcoin_verify_privkey( argv[2] )
			puts "Invalid sender private key #{argv[2]}" 
			return  
		end	
		
		utx =  make_raw_transaction( argv[0] , argv[1] , argv[2] , argv[3] ) 
		
		p utx
		tx  = make_signed_transaction( utx , argv[2] )

		puts "Drop the following into : https://blockchain.info/pushtx"
		puts tx

		
	else
		printf "Usage : ruby %s <from pubkey> <to pubkey> <privkey> <amount>\n", __FILE__
	end

end

main ARGV