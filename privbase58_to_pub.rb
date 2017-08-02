
require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	if argv.length > 0 

		privbase58 = argv[0]
		
		privnum = bitcoin_privbase58_to_privnum( privbase58 )
		privwif = bitcoin_privnum_to_wif( privnum )
		pubkey  = bitcoin_privnum_to_pubkey( privnum )

		printf "Privnum :\nDec : %d\nHex : 0x%x\nOct : 0%o\n" , privnum, privnum , privnum 
		puts   "Private key WIF 	: #{ privwif }"
		puts   "Public  key 		: #{ pubkey }"
	else
		printf "Usage : ruby %s <private key in base58>\n", __FILE__
	end	
end

main ARGV
