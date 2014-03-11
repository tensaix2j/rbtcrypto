
Ruby Bitcoin Toolkit
====================

Created for self educational purpose. Use it at your own risk. 


Usage
--------------

To get the public address from private key(WIF):


```sh
ruby priv_to_pub.rb <private key(WIF)>
```


To get the public address from private key number(256 bit number):


```sh
ruby privnum_to_pub.rb <private key(256 bit number)>
```



To generate new address:


```sh
ruby new_address.rb 
```

To verify address valid or not
```sh
ruby verify_address.rb <private key(WIF) or public address>
```

To generate key pairs from passphrase:


```sh
ruby brainwallet.rb <passphrase>
```


To craft Transaction and drop into https://blockchain.info/pushtx


```sh
ruby maketransaction.rb  <sender public address> <receiver public address> <sender private key(WIF)> <amount>
```




