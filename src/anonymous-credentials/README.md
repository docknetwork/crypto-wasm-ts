# Anonymous credentials 

This directory contains an [anonymous credentials](https://blog.dock.io/anonymous-credentials/) implementation using the [composite proof system](src/composite-proof/index.ts).

## Schema

Specifies all the fields of the credential and their structure (nesting). Because anonymous credentials allow to hide any 
number of attributes of the credential, it must be possible to know what attributes were part of the issued credential. Schema 
also defines the **encoding** of each attribute. Encoding determines how the credential attribute value must be converted to 
a positive integer ([prime field, a [finite field](https://en.wikipedia.org/wiki/Finite_field) of prime order, to be precise) 
before passing to the crypto (signing, proving) algorithms. Choosing an appropriate encoding process is essential when doing 
enforcing bounds on attributes (range proofs), verifiable encryption of attributes or when using it in [predicates](https://blog.dock.io/circom-language-integration/) written 
in [Circom](https://docs.circom.io/). For more details on the need of encoding see [here](README.md#encoding-for-negative-or-decimal-numbers) and 
[here](README.md#encoding-for-verifiable-encryption). 

Schema [code](src/anonymous-credentials/schema.ts) and [tests](tests/anonymous-credentials/schema.spec.ts).

## Credentials

A credential contains one or more attributes signed by the issuer; attributes and the signature together make up the credential. 
Anonymous credential allow to hide any number of attributes including the signature (always) while proving the knowledge of the signature by the issuer. 
A credential always contains a schema as one of the attribute (inline, not a reference) and the schema attribute is always revealed to the verifier.

A [CredentialBuilder](src/anonymous-credentials/credential-builder.ts) is used to build a credential by setting various attributes and 
then signed using the issuer's secret key resulting in a [Credential](src/anonymous-credentials/credential.ts) which can then be verified using the 
public key of the issuer. A credential might have a status field indicating whether the credential can be revoked or not. Currently only 1 
mechanism is supported and that is accumulator but the status property is oblivious to that.

See these [tests](tests/anonymous-credentials/credential.spec.ts) for examples of credential issuance, verification and (de)serialization.

## Presentations

A user/holder might have any number of credentials. To convince a verifier that he has the credentials by certain issuers and 
optionally reveal some attributes from across the credentials or prove certain properties about the attributes, it creates a 
presentation. Similar to credentials, these follow builder pattern and thus a [PresentationBuilder](src/anonymous-credentials/presentation-builder.ts) 
is used to create a [Presentation](src/anonymous-credentials/presentation.ts). The builder lets you add credentials (using `addCredential`), mark various attributes revealed 
(using `markAttributesEqual`), enforce bounds on attributes (using `enforceBounds`), verifiably encrypt attributes (using `verifiablyEncrypt`). 
The `PresentationBuilder` allows adding a `context` for specifying things like purpose of the presentation or any self attested claims 
or anything else and a `nonce` for replay protection.
As part a `Presentation`, included is a [PresentationSpecification](src/anonymous-credentials/presentation-specification.ts) which 
specifies what the presentation is proving like what credentials, what's being revealed, which attributes are being proven equal, 
bounds being enforced, attributes being encrypted and their ciphertext, accumulator used, etc. Note that any binary values needed in the 
`Presentation` JSON are encoded as base58.

See these [tests](tests/anonymous-credentials/presentation.spec.ts) for examples of presentation creation, verification and 
(de)serialization with use of the above-mentioned features.

## TODO

- Blind credential issuance
- Credentials without needing explicit schema where all fields are encoded using the same default encoder
- Accumulator usage in general, i.e. without using credentialStatus field.
- Pseudonyms in presentation