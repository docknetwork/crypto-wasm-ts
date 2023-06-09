# Anonymous credentials 

This directory contains an [anonymous credentials](https://blog.dock.io/anonymous-credentials/) implementation using the [composite proof system](./../composite-proof/index.ts).

## Schema

Specifies all the fields of the credential and their structure (nesting). Because anonymous credentials allow to hide any 
number of attributes of the credential, it must be possible to know what attributes were part of the issued credential. Schema 
also defines the **encoding** of each attribute. Encoding determines how the credential attribute value must be converted to 
a positive integer ([prime field, a [finite field](https://en.wikipedia.org/wiki/Finite_field) of prime order, to be precise) 
before passing to the crypto (signing, proving) algorithms. Choosing an appropriate encoding process is essential when doing 
enforcing bounds on attributes (range proofs), verifiable encryption of attributes or when using it in [predicates](https://blog.dock.io/circom-language-integration/) written 
in [Circom](https://docs.circom.io/). For more details on the need of encoding see [here](./../../README.md#encoding-for-negative-or-decimal-numbers) and 
[here](./../../README.md#encoding-for-verifiable-encryption). 
It expects the schema in the [JSON-schema syntax](https://json-schema.org/), draft-07. 

Schema [code](./schema.ts) and [tests](../../tests/anonymous-credentials/schema.spec.ts).

## Credentials

A credential contains one or more attributes signed by the issuer; attributes and the signature together make up the credential. 
Anonymous credentials allow to hide any number of attributes and the signature (always) while proving the knowledge of the signature by the issuer. 
A credential always contains a schema as one of the attribute (inline, not a reference) and the schema attribute is always revealed to the verifier.

A [CredentialBuilder](./credential-builder.ts) is used to build a credential by setting various attributes and 
then signed using the issuer's secret key resulting in a [Credential](./credential.ts) which can then be verified using the 
public key of the issuer. A credential might have a status field indicating whether the credential can be revoked or not. Currently only 1 
mechanism is supported and that is accumulator but the status property is oblivious to that.

See these [tests](../../tests/anonymous-credentials/credential.spec.ts) for examples of credential issuance, verification and (de)serialization.

## Presentations

A user/holder might have any number of credentials. To convince a verifier that he has the credentials by certain issuers and 
optionally reveal some attributes from across the credentials or prove certain properties about the attributes, it creates a 
presentation. Similar to credentials, these follow builder pattern and thus a [PresentationBuilder](./presentation-builder.ts) 
is used to create a [Presentation](./presentation.ts). The builder lets you add credentials (using `addCredential`), mark various attributes revealed 
(using `markAttributesEqual`), enforce bounds on attributes (using `enforceBounds`), verifiably encrypt attributes (using `verifiablyEncrypt`). 
The `PresentationBuilder` allows adding a `context` for specifying things like purpose of the presentation or any self attested claims 
or anything else and a `nonce` for replay protection.
As part a `Presentation`, included is a [PresentationSpecification](./presentation-specification.ts) which 
specifies what the presentation is proving like what credentials, what's being revealed, which attributes are being proven equal, 
bounds being enforced, attributes being encrypted and their ciphertext, accumulator used, etc. Note that any binary values needed in the 
`Presentation` JSON are encoded as base58.

See these [tests](../../tests/anonymous-credentials/presentation.spec.ts) for examples of presentation creation, verification and 
(de)serialization with use of the above-mentioned features.

## Blinded Credentials

A user/holder can request a blinded credential from the signer/issuer where some of the attributes are not known to the signer. The blinded credential needs to be then unblinded, i.e. converted to a normal credential which can be verified by the signer's public key and used in presentations. The workflow to do this is as follows: user uses a [BlindedCredentialRequestBuilder](./blinded-credential-request-builder.ts) to create [BlindedCredentialRequest](./blinded-credential-request.ts) which is sent to the signer and subsequently verified by the signer. On successful verification, the signer uses `BlindedCredentialRequest` to create a [BlindedCredentialBuilder](./blinded-credential-builder.ts) to build a [BlindedCredential](./blinded-credential.ts). The `BlindedCredential` is sent to the user who then converts it to a normal credential. The `BlindedCredentialRequest` contains a `Presentation` inside which is verified by the signer.  
The user while requesting such a credential might need to prove the possession of other credentials or prove that some of the blinded (hidden) attributes are same as the credentials in the presentation. The user can do this by calling methods on `BlindedCredentialRequestBuilder`, eg, calling `addCredentialToPresentation` will add a `Credential` already possessed by the user to the `Presentation` contained in the `BlindedCredentialRequest`, `enforceBoundsOnCredentialAttribute` will enforce bounds (min, max) on the credential attribute, etc. Any predicate supported in `Presentation`s can be proved over the credential added in `BlindedCredentialRequest`. Predicates can also be proven over the blinded attributes, eg, `markBlindedAttributesEqual` can be used to prove some blinded attribute equal to a credential attribute, `verifiablyEncryptBlindedAttribute` can be used to verifiably encrypt a blinded attribute, etc.

See these [tests](../../tests/anonymous-credentials/blind-issuance.spec.ts) for examples of using these predicates.



*Note that lot of classes mentioned above are abstract as this project supports multiple signature schemes.* 

## TODO

- Accumulator usage in general, i.e. without using credentialStatus field.
