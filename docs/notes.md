# Implementation Notes
We define (go) interface for:
* Quorum system
* Transport layer (including transport security)
* Node (certificate)
* Crypto package
  * signature scheme
  * message encryption / signature
  * collective signature
  * Keyring
  * RNG
* Storage (DB)

We implement (as of now):
* Quorum system with WoT
* Transport with HTTP
  * Transport security with PGP message encryption / signature
* Certificate with PGP key
  * Trust graph to manage nodes
* All crypto functions with PGP
  * PGP keyring to store certs, private key and revocation list
  * PGP key for certificate
  * PGP signatures in PGP key to construct the graph
  * PGP encryption / signature for transport security
  * PGP signature to sign <x,t,v>
  * PGP signature for collective signature
  * PGP User ID for the URL
* Storage with (plain) Unix file to store the value with the filename: "variable (hex string).timestamp", or with leveldb ("github.com/syndtr/goleveldb/leveldb")

In golang, we use "golang.org/x/crypto/openpgp" for the PGP operations. Except PGP and leveldb, we use the standard library only.

All messages are encrypted with the PGP key of recipients. With the PGP encryption scheme, a message is signed by the the sender and then encrypted only once with all recipient's keys. The same PGP packet is sent out to each recipient. 

The collective signature is just a series of the PGP signature packet in the current implementation. The reason why the interface defines the collective signature separated from the signature scheme is because of a possibility of replacing it with a threshold signature scheme in the future.

### Concurrent access to the local storage
The keyring and revocation list can be updated during the operations on memory only. When the process terminates both keyring and revocation list will be stored in the local storage (not using the storage interface). The value (with the signatures) will be stored in the storage (using the storage interface) on the spot. We assume the db is not shared among multiple processes. The db can be accessed concurrently from multiple threads.

## PGP Key
The following PGP packets are used in the system.
### Public-Key Packet
Must include the primary public key. The key is used to verify the signature to make the trust graph within the quorum system.
### Signature Packet
Represents trust incoming edges from signers. Must include the self-signed signature as specified in OpenPGP.
### Sub key packets
Inside the signature packet, at least one encryption key has to be included. The system uses the key for transport-security as well as encrypting messages.
### User ID Packet
Must include a unique ID. For end users, the ID must be an email address. For servers, the ID can be an URL, UUID or PGP fingerprint.
### User Attribute Packet
With subtype = 101,
Can include any data necessary for "email address proof", e.g., DKIM, SAML, OpenID.
### Revocation List Packet
A list of PIDs the node no longer trusts while it trusted before (therefore it signed the PGP certs).
