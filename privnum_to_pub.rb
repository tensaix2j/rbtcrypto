
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	if argv.length > 0 

		if argv[0][0...2] == "0x"
			privnum = argv[0].to_i(16)
		elsif argv[0][0...1] == "0"
			privnum = argv[0].to_i(8)
		else
			privnum = argv[0].to_i
		end

		assert ( "Private Key number must be > 0" ) { privnum > 0 }
		privwif = bitcoin_privnum_to_wif( privnum )
		pubkey  = bitcoin_privnum_to_pubkey( privnum )

		printf "Privnum :\nDec : %d\nHex : 0x%x\nOct : 0%o\n" , privnum, privnum , privnum 
		puts   "Private key WIF 	: #{ privwif }"
		puts   "Public  key 		: #{ pubkey }"
	else
		printf "Usage : ruby %s <private key 256bit number>\n", __FILE__
	end	
end

main ARGV
