
Ruby Bitcoin Toolkit
====================

Created for self educational purpose. Use it at your own risk. 

Reference: Python ecdsa library for elliptic curve multiplication, addition and inverse_mod operations.


Usage
--------------

To get the public address from private key:


```sh
ruby priv_to_pub.rb <private key>
```


To generate new address:


```sh
ruby new_address.rb 
```

To verify address valid or not
```sh
ruby verify_address.rb <private or public key>
```

To generate key pairs from passphrase:


```sh
ruby brainwallet.rb <passphrase>
```




