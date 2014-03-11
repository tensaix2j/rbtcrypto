
Ruby Bitcoin Toolkit
====================

Created for self educational purpose. Use it at your own risk. 


Usage
--------------

To get the public address from private key:


```sh
ruby priv_to_pub.rb <private key(WIF)>
```


To generate new address:


```sh
ruby new_address.rb 
```

To verify address valid or not
```sh
ruby verify_address.rb <private key(WIF) or public key>
```

To generate key pairs from passphrase:


```sh
ruby brainwallet.rb <passphrase>
```


To craft Transaction and drop into https://blockchain.info/pushtx


```sh
ruby maketransaction.rb  <sender public key> <receiver public key> <sender private key(WIF)> <amount>
```




