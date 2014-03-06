
require 'rubygems'
require 'open-uri'
require 'digest/sha2'
require 'bigdecimal'
require 'json'


@INFINITY = [nil,nil]

# secp256k1 setting:
@p 		= 115792089237316195423570985008687907853269984665640564039457584007908834671663
@a 		= 0
@b 		= 7
@G_x 	= 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
@G_y 	= 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
@order 	= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# elliptic curve multiplication, addition is based on python's ecdsa library implementation


@base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"



#---------------
def assert(msg=nil)
  	raise msg || "Assertion failed!" unless yield
end


#---------------
def leftmost_bit( x )

	assert { x > 0 }
	result = 1
	while x > 0
		x = x >> 1
		result *= 2
	end
	return result / 2
end


#---------
def div_mod( a,b )

	return [ a/b , a%b]
end


#---------
def inverse_mod( a , m )

	a = a % m if a < 0 or m <= a

  	# From Ferguson and Schneier, roughly:
  	c, d = a, m
	uc, vc, ud, vd = 1, 0, 0, 1
	while c != 0
		q, c, d = div_mod( d, c ) + [ c ]
		uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
	end	

	# At this point, d is the GCD, and ud*a+vd*m = d.
	# If d == 1, this means that ud is a inverse.
	assert { d == 1 }
	if ud > 0
		return ud	
	else
		return ud + m
	end
end

#---------------
# elliptic curve point * x
def mul( point, x , order = nil ) 

	e = x
	e = e % order if order
	return @INFINITY.dup if e == 0 || point == @INFINITY

	assert { x > 0 }
	e3 = 3 * e
	neg_point = [ point[0] , -point[1] ]
	i = leftmost_bit( e3 ) / 2
	result = point.dup

	while i > 1

		result = double(result)
		result = add(result, point )     if ( e3 & i ) != 0 && ( e & i ) == 0 
		result = add(result, neg_point ) if ( e3 & i ) == 0 && ( e & i ) != 0 
		i = i / 2
	end	
	
	return result
end


#---------------
# elliptic curve point * 2
def double( point )

	return @INFINITY.dup if point == @INFINITY

	l =  ( 3 * point[0] * point[0] + @a ) * inverse_mod( 2 * point[1] , @p ) % @p 
	x3 = ( l * l - 2 * point[0] ) % @p
	y3 = ( l * ( point[0] - x3 ) - point[1] ) % @p 

	return [ x3, y3]
end

#---------------
# elliptic curve point1 + point2
def add( point1, point2 )

	return point1.dup if point2 == @INFINITY
	return point2.dup if point1 == @INFINITY

	if point1[0] == point2[0] 
		if point1[1] + point2[1] % @p == 0
			return @INFINITY.dup
		else
			return double(point1)
		end
	end

	l = ((point1[1] - point2[1]) * inverse_mod( point1[0] - point2[0] , @p )) % @p
	x3 = (l * l - point1[0] - point2[0] )     % @p
	y3 = (l * ( point1[0] - x3 ) - point1[1]) % @p

	return [ x3, y3 ]
end
#-------
def base58str_tonum(x)

	sum = 0
	pos = 0
	x.reverse.each_char { |c|	
		sum += @base58_chars.index(c) * 58 ** pos
		pos += 1
	}
	return sum
end

#------
def number_to_base58str( n )

	str = ""
	while n > 0
		str.insert( 0 , @base58_chars[ n % 58 ].chr ) 
		n /= 58
	end	
	return str 
end	

#-----
def number_to_string( num , order )

	l = ( 1 + order.to_s(16).length ) / 2
	fmt_str = "%0#{ 2*l }x"
    return  fmt_str % num

end

#-----------------------
def hexlify(msg)
	msg.unpack("H*")[0]
end

#-----------------
def unhexlify(msg)
	[msg].pack("H*")
end


#------------
def bitcoin_privnum_to_pubkey( privkey_num )

	pubkey_point = mul( [ @G_x, @G_y] , privkey_num )
	
	x_str = number_to_string(  pubkey_point[0] , @order )
	y_str = number_to_string(  pubkey_point[1] , @order )
	
	pubkey_sha256 =  Digest::SHA256.hexdigest( unhexlify( "04" + x_str + y_str ) )
	pubkey_ripemd160 =  Digest::RMD160.hexdigest( unhexlify( pubkey_sha256 ) )

	# now the checksum
	chksum_sha256_r1 = Digest::SHA256.hexdigest( unhexlify( "00" + pubkey_ripemd160 ) )
	chksum_sha256_r2 = Digest::SHA256.hexdigest( unhexlify( chksum_sha256_r1 ) )

	pubkey_num = ( pubkey_ripemd160 + chksum_sha256_r2[0...8]).to_i(16)
	pubkey_base58 = number_to_base58str( pubkey_num )
	return "1" + pubkey_base58
end


#---------------
	
def bitcoin_privkey_to_pubkey( privkey )	

	assert("Invalid Address") { bitcoin_verify_privkey( privkey ) }
	# stripping off the checksum
	privnum = bitcoin_wif_to_privnum( privkey )
	return bitcoin_privnum_to_pubkey( privnum )

end

#-----------
def zfill( str, zlen ) 
	return zlen - str.length > 0 ? "0" * ( zlen - str.length ) + str : str
end



#-----
# private key to wallet import format
def bitcoin_privnum_to_wif( num )

	extended_hexstr =  "80" + zfill( num.to_s(16) , 64 ) 
	# private key checksum ...
	r1 = Digest::SHA256.hexdigest( unhexlify(extended_hexstr) )
	r2 = Digest::SHA256.hexdigest( unhexlify(r1) )

	return number_to_base58str( (extended_hexstr + r2[0...8] ).to_i(16) )
end


#-----
# wallet import format to private key
def bitcoin_wif_to_privnum( wif ) 

	return base58str_tonum( wif )/ (2**32) % (2**256)
end

#-----
def bitcoin_generate_key_pair() 

	# Todo: Use a better random seed.
	privnum = rand(  2 ** 256 )  % @order
	privkey = bitcoin_privnum_to_wif( privnum )
	pubkey  = bitcoin_privnum_to_pubkey( privnum )

	return [ privkey , pubkey ]

end



#-----
def bitcoin_generate_key_pair_by_passphrase( passphrase ) 

	passphrase_sha256 =  Digest::SHA256.hexdigest( passphrase )
		
	privnum = passphrase_sha256.to_i(16)
	privkey =  bitcoin_privnum_to_wif( privnum )
	pubkey  =  bitcoin_privnum_to_pubkey( privnum )

	return [ privkey , pubkey ]
	
end






#-------
def bitcoin_verify_pubkey( pubkey ) 

	pubkey_num_with_chksum 	= base58str_tonum( pubkey )
	pubkey_chksum 	 		= pubkey_num_with_chksum % (2**32)
	pubkey_num 		 		= pubkey_num_with_chksum / (2**32)

	# sha 2 times to get the chksum
	r1 = Digest::SHA256.hexdigest( unhexlify( zfill( pubkey_num.to_s(16), 42 ) )  )
	r2 = Digest::SHA256.hexdigest( unhexlify(r1) )

	return r2[0...8].to_i(16) == pubkey_chksum

end

#----
def bitcoin_verify_privkey( privkey ) 

	return bitcoin_privnum_to_wif( bitcoin_wif_to_privnum( privkey ) ) == privkey
end

#-

#----------
def get_balance( pubkey ) 
	
	url = "http://blockchain.info/address/#{ pubkey }?format=json"
 	res = JSON.parse(open(url).read)
	balance = BigDecimal.new(res["final_balance"]) / 100000000

	return balance
end

#----------
def get_unspent( pubkey ) 

	url = "https://blockchain.info/unspent?active=#{ @pubkey }&format=json"
	res = JSON.parse(open(url).read)
	unspent_outputs = res["unspent_outputs"]
	return unspent_outputs
end


#-----
# In progress...
def make_raw_transaction( sender_privkey, sender_prev_transaction_hash, sender_pubkey, recipient_pubkey , amount ) 
	
	

	#return 	"01000000" + 	# 4 bytes version
    #		"01" + 			# varint for number of inputs
    #		outputTransactionHash.decode('hex')[::-1].encode('hex') + # reverse outputTransactionHash
    #		struct.pack('<L', sourceIndex).encode('hex') +
    #		'%02x' % len(scriptSig.decode('hex')) + scriptSig +
    #		"ffffffff" + # sequence
    #		"%02x" % len(outputs) + # number of outputs
    #		formattedOutputs +
    #		"00000000" # lockTime
    		
end








