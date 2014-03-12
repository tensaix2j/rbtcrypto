
require 'rubygems'
require 'open-uri'
require 'digest/sha2'
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

#-------------
def sign_with_privnum( privkey_num , msg )

	msg_hexstr = hexlify(msg)
	msg_num    = msg_hexstr.to_i(16)

	k = rand(@order-1) + 1  
	#k = 15672977351170312799829257531283026088254387808041898846011970415821208542635

	p1 = mul( [ @G_x, @G_y] , k )
	r = p1[0]	
	s = ( inverse_mod( k, @order ) * ( msg_num + ( privkey_num * r ) % @order ) ) % @order
	
	r_str = number_to_string( r, @order ) 
	s_str = number_to_string( s, @order )

	return der_encode_sequence( [ der_encode_integer(r), der_encode_integer(s) ] ) + "\x01"

end

#----
def der_encode_integer( r )

	assert("r >= 0") { r >= 0 }
	h = r.to_s(16) 
    h = "0" + h if h.length % 2 == 1
    s = unhexlify(h)
    num = s[0].ord
    return "\x02" +  ((num <= 0x7f) ? s.length.chr : (s.length + 1).chr + "\x00"  ) + s
end

#----
def der_encode_sequence( encoded_pieces )
    
    total_len = 0
	encoded_pieces.each { |piece|
		total_len += piece.length
	}

	return "\x30" + der_encode_length(total_len) + encoded_pieces.join("")

end

#---
def der_encode_length( l)

	assert("l >= 0") { l >= 0 }
	if l < 0x80
        return l.chr
    end
	s = l.to_s(16)
    s = "0" + s if s.length % 2 == 1
    s = unhexlify(s)
    return ( 0x80  | s.length ).chr + s
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



#-----
# private key to wallet import format
def bitcoin_privnum_to_wif( num )

	extended_hexstr =  "80" +  num.to_s(16).rjust( 64, "0" ) 
	# private key checksum ...
	r1 = Digest::SHA256.hexdigest( unhexlify(extended_hexstr) )
	r2 = Digest::SHA256.hexdigest( unhexlify(r1) )

	return number_to_base58str( (extended_hexstr + r2[0...8] ).to_i(16) )
end


#-----
# wallet import format to private key
def bitcoin_privkey_to_privnum( privkey) 
	return bitcoin_wif_to_privnum( privkey )
end

# Same thing
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


#----
def pubkey_to_pubnum( pubkey )

	pubkey_num_with_chksum 	= base58str_tonum( pubkey )
	pubkey_chksum 	 		= pubkey_num_with_chksum % (2**32)
	pubkey_num 		 		= pubkey_num_with_chksum / (2**32)

	return pubkey_num

end


#-------
def bitcoin_verify_pubkey( pubkey ) 

	pubkey_num_with_chksum 	= base58str_tonum( pubkey )
	pubkey_chksum 	 		= pubkey_num_with_chksum % (2**32)
	pubkey_num 		 		= pubkey_num_with_chksum / (2**32)

	# sha 2 times to get the chksum
	r1 = Digest::SHA256.hexdigest( unhexlify(  pubkey_num.to_s(16).rjust( 42, "0")  )  )
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
	balance = res["final_balance"]

	return balance
end

#----------
def get_unspent( pubkey ) 

	require "net/http"
	require 'openssl'

	uri = URI.parse("https://blockchain.info/unspent?")
	args = {active: pubkey, format: "json" }

	uri.query = URI.encode_www_form(args)
	http = Net::HTTP.new(uri.host, uri.port)
	http.use_ssl = true
	http.verify_mode = OpenSSL::SSL::VERIFY_NONE
	request = Net::HTTP::Get.new(uri.request_uri)
	response = http.request(request)

	unspent_outputs = nil
	begin
		if response.body[/No free outputs to spend/]
			puts "No free outputs to spend!!"
		else	
			res = JSON.parse(  response.body )
			unspent_outputs = res["unspent_outputs"]
		end
	rescue Exception=>e
		
	end

	return unspent_outputs

end




#----------------
# Reference: https://gist.github.com/Sjors/5574485#file-bitcoin-pay-rb-L265
 
 #-----------
def make_raw_transaction( sender_pubkey, recipient_pubkey , amount, transaction_fee = 0  ) 
	
	sender_pubnum 		= pubkey_to_pubnum( sender_pubkey )
	recipient_pubnum 	= pubkey_to_pubnum( recipient_pubkey )

	transaction_fee = transaction_fee.to_i
	inputs = []

	unspent_outputs = get_unspent( sender_pubkey )
	assert("No unspent outputs") { unspent_outputs }

	input_total = 0
	unspent_outputs.each do |output|
	    
	    input = {}
	    input[:previousTx] 	= [output["tx_hash"]].pack("H*").reverse.unpack("H*")[0]
	    input[:index] 		= output["tx_output_n"]
	    inputs << input
	    
	    input_total +=  output["value"].to_i
	    puts "Using #{amount} satoshis from output #{output["tx_output_n"]} of transaction #{output["tx_hash"][0..5]}..."
	    break if input_total >= amount + transaction_fee
	end

	change = input_total - transaction_fee - amount
	puts "Spend #{amount} satoshis and return #{ change } satoshis as change."
 
	raise "Unable to process inputs for transaction" if input_total < amount + transaction_fee || change < 0
 	
	# Blockchain does not give this...So use the default.

	# A Typical script looks like this:
	
	# 76       A9             0x14 
	#OP_DUP OP_HASH160    Bytes to push

	#89 AB CD EF AB BA AB BA AB BA AB BA AB BA AB BA AB BA AB BA   88         AC
	#                      Data to push                     OP_EQUALVERIFY OP_CHECKSIG

	
 	inputs.each { |input|
		
		input[:scriptLength] 	= 25
		input[:scriptSig] 		= "OP_DUP OP_HASH160 14 #{ sender_pubnum.to_s(16) } OP_EQUALVERIFY OP_CHECKSIG" 
		input[:sequence_no] 	= "ffffffff"  
	} 
	
 	
	outputs = []

	
 	output = {}
 	output[:value] = amount
 	output[:pubkeyScriptLength] = 25
 	output[:pubkeyScript] = "OP_DUP OP_HASH160 14 #{ recipient_pubnum.to_s(16) } OP_EQUALVERIFY OP_CHECKSIG" 
 	outputs << output		

 	if change > 0

 		output = {}
	 	output[:value] = change
	    output[:pubkeyScriptLength] = 25
	    output[:pubkeyScript] = "OP_DUP OP_HASH160 14 #{ sender_pubnum.to_s(16) } OP_EQUALVERIFY OP_CHECKSIG"
		outputs << output
	end   
 	
	

	transaction = {
		:version => 1,
		:in_counter => inputs.count,
		:inputs => inputs,
		:out_counter => outputs.count,
		:outputs => outputs,
		:lock_time => 0,
		:hash_code_type => "01000000"
	}

	
    return transaction
end


#----------------------
def bitcoin_privnum_to_pubkey65_hexstring( privkey_num )

	pubkey_point = mul( [ @G_x, @G_y] , privkey_num )
	
	x_str = number_to_string(  pubkey_point[0] , @order )
	y_str = number_to_string(  pubkey_point[1] , @order )
	
	return "04" + x_str + y_str 

end

#---------------
def make_signed_transaction( transaction , privkey )

	raw_transaction = serialize_transaction( transaction )	

	sha_first = (Digest::SHA2.new << [raw_transaction].pack("H*")).to_s
	sha_second = (Digest::SHA2.new << [sha_first].pack("H*")).to_s
	 
	puts "\nHash that we're going to sign: #{sha_second}"
	 
	privkey_num    		= bitcoin_wif_to_privnum( privkey )
	pubkey65_hexstring  = bitcoin_privnum_to_pubkey65_hexstring( privkey_num )

	
	signature_binary 	= sign_with_privnum( privkey_num , sha_second )
	signature 			= signature_binary.unpack("H*").first
	 
	hash_code_type 						 = "01"
	signature_plus_hash_code_type_length = (signature + hash_code_type).length / 2
	pub_key_length 						 = pubkey65_hexstring.length / 2
	

	scriptSig = signature_plus_hash_code_type_length.to_s + signature + hash_code_type + pub_key_length.to_s  + pubkey65_hexstring
	 
	# Replace scriptSig and scriptLength for each of the inputs:
	transaction[:inputs].each { |input| 
	  
	    input[:scriptLength] 	= scriptSig.length / 2
	    input[:scriptSig] 		= scriptSig
	}
	 
	transaction[:hash_code_type] = ""

	signed_transaction = serialize_transaction( transaction )
		 
	return signed_transaction

end


#---------------
def little_endian_hex_of_n_bytes(i, n) 
	i.to_s(16).rjust(n * 2,"0").scan(/(..)/).reverse.join()
end
 
#----
def reverse_byte_order(str)
	return str.scan(/(..)/).reverse.join()
end

#---------------
def parse_script(script)
	script.gsub("OP_DUP", "76").gsub("OP_HASH160", "a9").gsub("OP_EQUALVERIFY", "88").gsub("OP_CHECKSIG", "ac").gsub(" ","")
end
 


#---------------
def serialize_transaction(transaction)
  
	tx = ""
	# Little endian 4 byte version number: 1 -> 01 00 00 00
	tx << little_endian_hex_of_n_bytes(transaction[:version],4)
	# You can also use: transaction[:version].pack("V") 
	 
	# Number of inputs
	tx << little_endian_hex_of_n_bytes( transaction[:in_counter], 1 )
	transaction[:inputs].each do |input|
		tx << little_endian_hex_of_n_bytes(input[:previousTx].hex, input[:previousTx].length / 2)
		tx << little_endian_hex_of_n_bytes(input[:index],4) 
		tx << little_endian_hex_of_n_bytes(input[:scriptLength],1)
		tx << parse_script(input[:scriptSig])
		tx << input[:sequence_no] 
	end
	  
	# Number of outputs
	tx << little_endian_hex_of_n_bytes(transaction[:out_counter],1)
	  
	transaction[:outputs].each do |output|
		tx << little_endian_hex_of_n_bytes( output[:value].to_i, 8) 
		unparsed_script = output[:pubkeyScript]
		# Parse the script commands into hex opcodes (yes this is lame):
		tx << little_endian_hex_of_n_bytes( parse_script(unparsed_script).length / 2 , 1 ) 
		tx << parse_script(unparsed_script)
	end
	  
	tx << little_endian_hex_of_n_bytes(transaction[:lock_time],4)
	tx << transaction[:hash_code_type] # This is empty after signing
	
end



#------------

def get_var_length_val( transaction_hex, pt )

	val = transaction_hex[ (pt * 2)...(pt + 1)*2 ].to_i(16)
	pt_off = 1

	if val == 0xfd  
		val = transaction_hex[ (pt+1)*2...(pt+3)*2].to_i(16)
		pt_off = 3
	elsif val == 0xfe 
		val = transaction_hex[(pt+1)*2...(pt+5)*2].to_i(16)
		pt_off = 5
	elsif val == 0xff
		val = transaction_hex[(pt+1)*2...(pt+9)*2].to_i(16)
		pt_off = 9
	end

	return [ val , pt_off ]

end


# Put the hex string back to data structure
def deserialize_transaction( transaction_hex ) 

	transaction = {}
	transaction[:version] 		= reverse_byte_order( transaction_hex[0...8] ).to_i(16)
	transaction[:in_counter] 	= transaction_hex[8...10].to_i(16)
	pt = 4

	get_next_val 				= get_var_length_val( transaction_hex, pt )
	transaction[:in_counter] 	== get_next_val[0]
	pt += get_next_val[1]

	
	transaction[:inputs] = []
	(0...transaction[:in_counter]).each { | i |
		
		input = {}
		input[:prevhash] 		= reverse_byte_order( transaction_hex[ (pt * 2)...(pt + 32)*2 ] )
		pt += 32
		input[:prevoutputindex] = reverse_byte_order( transaction_hex[ (pt * 2)...(pt + 4)*2 ] ).to_i(16)
		pt += 4

		get_next_val 			= get_var_length_val( transaction_hex, pt )
		input[:scriptLength] 	= get_next_val[0]	
		pt += get_next_val[1]

		script_sig = []
		(0...input[:scriptLength]).each { |j|
			script_sig << transaction_hex[ (pt * 2)...(pt + 1)*2]
			pt += 1
		}
		input[:scriptSig] = script_sig.join(" ")
		input[:sequence] = transaction_hex[ (pt * 2)...(pt + 4)*2]
		pt += 4
		transaction[:inputs] << input
	}
	
	get_next_val 				= get_var_length_val( transaction_hex, pt )
	transaction[:out_counter] 	= get_next_val[0]
	pt += get_next_val[1]
	

	transaction[:outputs] = []
	(0...transaction[:out_counter]).each { |i| 
		output = {}
		output[:value] = reverse_byte_order( transaction_hex[ (pt * 2)...(pt + 8)*2] ).to_i(16)
		pt += 8

		get_next_val = get_var_length_val( transaction_hex, pt )
		output[:pubkeyScriptLength] =  get_next_val[0]
		pt += get_next_val[1]

		pubkeyScriptSig = []
		(0...output[:pubkeyScriptLength]).each { |j| 
			pubkeyScriptSig <<  transaction_hex[ (pt * 2)...(pt + 1)*2]
			pt += 1
		}
		output[:pubkeyScriptSig] = pubkeyScriptSig

		transaction[:outputs] << output
	}

	transaction[:lock_time] = transaction_hex[ (pt * 2)...(pt + 4)*2]

	return transaction
end



