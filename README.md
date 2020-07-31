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
