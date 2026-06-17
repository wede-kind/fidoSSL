# fidoSSL Changelog



## Message changes

### Pre-Registration Indication

- has been renamed to Pre Indication

### Pre-Registration Request

- has been renamed to Pre Request

### Pre-Registration Response

- removed

### Registration Indication

- message type is now 3
- added user name, which is encrypted with the AES key
- added user display name, which is encrypted with the AES key
- added ticket, which is encrypted with the AES key

### Registration Request

- message type is now 4
- Authenticator Selection is now a CBOR array, all 3 values ***have*** to be set,
  if the Authentication Selection is used
- the Authenticator Selection now has the key 2 in the optionals map
- the Excluded Credentials now have the key 3 in the optionals map

### Registration Response

- message type is now 5
- now correctly uses the complete attestation object

### Authentication Indication

- message type is now 6

### Authentication Request

- message type is now 7

### Authentication Response

- message type is now 8
- user handle is now part of a CBOR map called optionals with key 1
- Selected Credential ID is now part of a CBOR map called optionals with key 2
- both User Handle and Selected Credential ID are not actually optional, as only 
  discoverable credentials can be used as of now

## Other Changes

- added option to use SSLKEYLOGFILE to log SSL session keys