# did-security-c#
C# implementation of DID security and privacy controls

The current focus is on pairwise key generation with the following algorithms.

# Pairwise ID generation scheme based on Elliptic Curves
The first use of pairwise IDs is to generate a pairwise ID whenever a user interacts with a new relying party. 
Since we don�t know all relying parties ahead of time, we must be able to generate a new pairwise DID just in time. 
This scheme is designed to create a unique elliptic curve key pair for each combination of a peer identifier and the DID of the user.
The scheme allows us to recreate all parameters needed for persisting the pairwise id�s cross different user agents or recover in case a user agent got lost.


## Important parameters
**Seed**	256 bit value that the user needs to reproduce on each user agent.

**usage**	String value representing the usage of the generated key

**Did**	A decentralized identifier registered by the user

**didMasterKey**	Derived master key for each DID used in the user agent

**peerId**	Identifier representing the relying party or peer

**privKey(didMasterKey, peerId)**	Private key to be used for the DID and the peer

**pubKey(didMasterKey, peerId)**	Public key to be used for the DID and the peer


## Deterministic EC key generation protocol for pairwise Id's
The following provides us with a unique master key per operation for the DID on the user agent:
		Let didMasterKey = HMAC-SHA512(Key = seed, data = usage || did).

		
		Let usage be 'signature' for a signature key, 'encryption' for an encryption key. 'none' can be used if the same key is used for both operations.


		Let peerId be a representation string of the peer or relying party. The peerId could be any string but needs to be clearly discoverable in any transactions. 
		
		To generate the same pairwise id, the peerId must always be deterministic for each peer or relying party. 
		
		We need to make sure the peerid has defined canonicalization and localization transformations so each user agent will come to the same binary representation of the peerId. 
		
		Examples of peerId's are the DID of the peer in the transactions, domain name of a relying party. 


To calculate the pairwise key pair for each peer, perform the following: 
		Let peerKey(didMasterKey, peerId) = HMAC-SHA512(Key = didMasterKey, Data = peerId).


Now we need to normalize the peerKey to make it a valid EC private key:
		privKey(didMasterKey, peerId) =  peerKey(didMasterKey, peerId) mod n

n is the modulus which is a parameter of the curve.


# Pairwise ID generation scheme based on RSA

This section defines a scheme how to generate a new pairwise key just in time for RSA. 

This scheme is designed to create a unique RSA key pair for each combination of a peer identifier and the DID of the user.

The scheme allows us to recreate all parameters needed for persisting the pairwise id’s cross different user agents or recover in case a user agent got lost.

## Important parameters
**Seed**	256 bit value that the user needs to reproduce on each user agent.
**Usage**	String value representing the usage of the generated key
**Did**	A decentralized identifier registered by the user
**didMasterKey**	Derived master key for each DID used in the user agent
**peerId**	Identifier representing the relying party or peer
**privKey(didMasterKey, peerId)**	Private key to be used for the DID and the peer
**pubKey(didMasterKey, peerId)**	Public key to be used for the DID and the peer

## Deterministic key protocol for pairwise Id's
The following provides us with a unique master key for the DID on the user agent:

		Let didMasterKey = HMAC-SHA512(Key = seed, data = usage || did).

		Let usage be “signature” for a signature key, “encryption” for an encryption key. “none” can be used if the same key is used for both operations.

		Let peerId be a representation string of the peer or relying party. The peerId could be any string but needs to be clearly discoverable in any transactions. To generate the same pairwise id, the peerId must always be deterministic for each peer or relying party. We need to make sure the peerid has defined canonicalization and localization transformations so each user agent will come to the same binary representation of the peerId. Examples of peerId’s are the DID of the peer in the transactions, domain name of a relying party. 

We will need two prime numbers p and q needed for the RSA key pair generation. The size of p and q is equal to the RSA key length / 2. So, a 2048 bits RSA key pair will need two deterministic values pbase, qbase of 1024 bits. We will need two SHA512 operations to get a 1024 bits value.

		Let pbase =  (x = HMAC-SHA512(Key = didMasterKey, data = peerId)) || HMAC-SHA512(Key = didMasterKey, data = x)

		Let qbase =  (x = HMAC-SHA512(Key = pbase, data = peerId)) || HMAC-SHA512(Key = pbase, data = x)
pbase and qbase will be converted into positive big integers and are considered to be in the big endian format. The most and least significant bits are set to 1 to guarantee an odd and large number.
Next, we need a deterministic prime generator. The algorithm will be identical for generating p and q.


We use the Miller-Rabin primality test (isPrime) with 64 iterations. 64 iterations will guarantee 128 bits security.

### Pseudo code for calculating p:
		Let primeToTest = pbase;
		While (true)
		{
			If (isPrime(primeToTest, 64))
				return primeToTest;
			primeToTest += 2;
		}

Now that we have p and q we can calculate the full RSA key as follows:

		n = pq
		e = 65537
		d = e-1 mod ((p - 1)(q - 1))
		Let privKey(didMasterKey, peerId) = d,n 
		Let pubKey(didMasterKey, peerId) = e,n 

