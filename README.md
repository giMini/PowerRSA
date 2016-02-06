# PowerRSA
Generate RSA keys, encrypt and decrypt data

# Generate the keys 

To generate the Modulus, the private key and the public key, enter this command

.\PowerRSA.ps1 -Method GenKeys 


# Encrypt data

To encrypt data using PowerRSA enter this command

.\PowerRSA.ps1 -Method Enc -Exponent F:\Crypto\20160206104626\PublicKey -Modulus F:\Crypto\20160206104626\Modulus 

Enter the data string to encrypt : 

Enter message to encrypt: Hi! I'm an encrypted data string 

# Decrypt data

To decrypt data using PowerRSA enter this command

.\PowerRSA.ps1 -Method Dec -Data F:\Crypto\20160206110641\Data -Exponent F:\Crypto\20160206104626\PrivateKey -Modulus F:\Crypto\20160206104626\Modulus 
