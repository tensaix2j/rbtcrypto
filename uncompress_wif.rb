require_relative 'lib/rbtcrypto.rb'

#-------------
def main( argv )
	
	if argv.length > 0 
		p uncompress_wif( argv[0] ) 
	else
		printf "Usage : ruby %s <compressed_wif Kxxxx or Lxxx>\n", __FILE__
	end

end

main ARGV
