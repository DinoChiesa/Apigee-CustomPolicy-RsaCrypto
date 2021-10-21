# RSA Crypto callout

This directory contains the Java source code for a Java callout for Apigee that
performs RSA Encryption and Decryption of data or message payloads, or RSA
signing of data or message payloads, or verification of such signatures.

Specifically it can perform:
* RSA encryption or decryption with PKCS1 padding.
* RSA encryption or decryption with OAEP padding, using SHA-256 as the primary and MGF1 hash functions. (For more on OAEP, see [this](https://stackoverflow.com/a/49484492/48082).)
* RSA signing with PKCS V1.5 padding or PSS padding. With the latter you can specify the primary and MGF1 hash functions.


There are two callout classes:
* com.google.apigee.callouts.RsaCrypto
* com.google.apigee.callouts.RsaSignature

The former does encryption and decryption. The latter does signing and verification.

## Background on Encryption

There are payload size limits when you encrypt using RSA keys. In more detail,
RSA, as defined by PKCS#1, can be used to encrypt messages of limited size. In
fact, an encrypted message always has the same size as the modulus; for a
1024-bit RSA key, this means 128 bytes. for a 2048-bit RSA key, 256 bytes. The
encryption process includes some padding. With the commonly used "v1.5 padding"
and a 2048-bit RSA key, the maximum size of data that can be encrypted with RSA
is 245 bytes. ([cite](https://security.stackexchange.com/a/33445/81523)) For
OAEP padding and the same 2048-bit key, the maximum size is 214 bytes.

This may seem to be a severe limitation. But, in practice people avoid this
limitation by using hybrid cryptosystems: use RSA encryption to encrypt a
symmetric key, which is small, and fits under the limit for RSA crypto. Then use
that symmetric key to AES-encrypt a larger message. There are two keys - the
first key encrypts the second key; let's call the first key the
key-encrypting-key. The second key encrypts the content, let's call it the
content-encrypting-key (CEK).

Then the encrypting party can send the encrypted payload along with the
encrypted content-encrypting-key. The decrypting party uses the private RSA key
to decrypt the CEK, then uses the decrypted CEK to decrypt the payload.

This common pattern is known as a
["hybrid cryptosystem"](https://en.wikipedia.org/wiki/Hybrid_cryptosystem). This
model is used in TLS, encrypted JWT, PGP, S/MIME, and many other security
protocols.

The general pattern for encryption is:

1. generate a random AES key,
2. encrypt the plaintext with that key using AES with some specific mode, IV, etc.
3. encrypt the AES key with RSA
4. concatenate those two ciphertexts in some way in the output stream, and transmit
   that to the trusted receiver. (You probably also need to transmit the IV)

## This callout does not perform hybrid crypto

This callout does not perform hybrid cryptography.
This callout does only RSA crypto. It can do two things:

- encrypt a small payload with an RSA public key; this corresponds to the 3rd step in the above.
- decrypt a small payload with an RSA private key. This would be the converse of the above.

When encrypting, the callout policy can also generate a random key; this
corresponds to the 1st step in the above.

If you want to implement the hybrid cryptosystem, then you'll want to couple
this callout with something that does AES crypto. For that you may want to use
the [AES Crypto callout](https://github.com/DinoChiesa/Apigee-CustomPolicy-AesCrypto).

By the way, this pattern is what underlies the "encrypted JWT" standard when
using asymmetric keys.


## License

This code is Copyright (c) 2017-2021 Google LLC, and is released under the
Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Using the Custom Policy

You do not need to build the Jar in order to use the custom policy.

When you use the policy to encrypt data, the resulting cipher-text can be
decrypted by other systems. Likewise, the policy can decrypt cipher-text
obtained from other systems. To do that, the encrypting and decrypting systems
need to use a matched key pair (public and private), the same padding (either
PKCS1 or OAEP).

The policy performs only RSA crypto.


## Policy Configuration

There are a variety of options, which you can select using Properties in the configuration. Examples follow, but here's a quick summary:

- the policy uses as its source, the message.content. If you wish to encrypt, decrypt, sign or verify something else, specify it with the source property
- When encrypting,
  - the policy always uses ECB, which is sort of a misnomer since it's a single block encryption.
  - when using OAEP padding, the policy uses SHA-256 and MGF1 as the hashes. You cannot override either of those. The MGF1 internally by default uses SHA-256, and  you _can_ override that with the mgf1-hash property. Specify one of {SHA1, SHA256, SHA384, SHA512}.

- you can optionally encode (base64, base64url, base16) the output byte stream upon encryption or signing.

- When decrypting,
  - you can optionally UTF-8 decode the output octet stream upon decryption.


## Example: Signing with PKCS v1.5 padding

  ```xml
  <JavaCallout name="Java-RsaSign">
    <Properties>
      <Property name='action'>sign</Property>
      <Property name='private-key'>{my_private_key}</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.RsaSignature</ClassName>
    <ResourceURL>java://apigee-callout-rsa-crypto-20211020.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this policy configuration:

* the `action` is sign, and the class is RsaSignature, so the policy will generate a signature.
* No `source` property is specified, therefore this policy will sign the message.content.
* When using the policy to sign, you must specify a private key. With the above configuration, the policy will deserialize the private key from the PEM string contained in the variable `my_private_key`.
* There is no `padding` property specified, so the policy will use PKCS v1.5 padding.
* No `output` property is present, so the policy will encode the resulting ciphertext via base64, and store it into a variable named signing_output (the default).

To verify the resulting signature, either within Apigee with this policy, or
using some other system, the verifier needs to use the corresponding public
key, and the same padding.

## Example: Signing with PSS Padding

  ```xml
  <JavaCallout name="Java-RsaSign">
    <Properties>
      <Property name='action'>sign</Property>
      <Property name='private-key'>{my_private_key}</Property>
      <Property name='padding'>PSS</Property>
      <Property name='encode-result'>base64url</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.RsaSignature</ClassName>
    <ResourceURL>java://apigee-callout-rsa-crypto-20211020.jar</ResourceURL>
  </JavaCallout>
  ```

This policy works like the prior example, with these exceptions:

* The `padding` property tells the policy to use PSS padding. There is no `pss-hash` or `mgf1-hash` property, so those default to `SHA-256`.


To verify the resulting signature, either within Apigee with this policy, or
using some other system, the verifier needs to use the corresponding public
key, and PSS padding, with SHA-256 as the primary hash and the mgf1 function.

## Example: Verifying with PSS Padding

  ```xml
  <JavaCallout name="Java-RsaSign">
    <Properties>
      <Property name='action'>verify</Property>
      <Property name='public-key'>{my_public_key}</Property>
      <Property name='padding'>PSS</Property>
      <Property name='decode-signature'>base64url</Property>
      <Property name='signature-source'>request.header.signature</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.RsaSignature</ClassName>
    <ResourceURL>java://apigee-callout-rsa-crypto-20211020.jar</ResourceURL>
  </JavaCallout>
  ```

This policy verifies a base64url-encoded signature using PSS padding, using
SHA-256 for both the primary and MGF1 hashes.

## Example: Basic Encryption with Numerous Defaults

  ```xml
  <JavaCallout name="Java-RsaEncrypt1">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='public-key'>{my_public_key}</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.RsaCrypto</ClassName>
    <ResourceURL>java://apigee-callout-rsa-crypto-20211020.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this policy configuration:

* the `action` is encrypt, and the class is RsaCrypto, so the policy will encrypt.
* No `source` property is specified, therefore this policy will encrypt the message.content.
* When using the policy to encrypt, you must specify a public key. With the above configuration, the policy will deserialize the public key from the PEM string contained in the variable `my_public_key`.
* There is no `padding` property specified, so the policy will use PKCS1 padding.
* No `output` property is present, so the policy will encode the resulting ciphertext via base64, and store it into a variable named crypto_output (the default).

To decrypt the resulting ciphertext, either within Apigee with this policy, or
using some other system, the decryptor needs to use the corresponding private
key, and the same padding.


## Example: Generate an AES key and Encrypt it

  ```xml
  <JavaCallout name="Java-RsaEncrypt2">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='public-key'>{my_public_key}</Property>
      <Property name='generate-key'>true</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.RsaCrypto</ClassName>
    <ResourceURL>java://apigee-callout-rsa-crypto-20211020.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this policy configuration:

* the `action` is encrypt, so the policy will encrypt
* the `generate-key` property is true, so
  Because `generate-key` is true, the policy will generate a 128-bit random key and use that as the "source", or the thing to encrypt. The policy will ignore a `source` property when `generate-key` is true.
* The policy will deserialize the public key from the PEM string contained in the variable `my_public_key`
* There is no` padding` specified, so PKCS1Padding is used.
* The policy stores the outputs - the generated key in cleartext, and the ciphertext for that
  key (in other words, the encrypted version) - into context variables named `crypto_output_key` and `crypto_output`, encoded via base64.

The proxy can subsequently use the encoded AES key to encrypt something via AES.  The
caller can then send the ciphertext output (the encrypted key) of this policy,
along with the ciphertext of the AES encryption step, to a receiver. The
receiver can decrypt the encrypted AES key using the RSA private key, and the
same padding. Then the receiver can decrypt the AES-encrypted ciphertext with
the recovered AES key.

### Example: Basic Decryption

  ```xml
  <JavaCallout name="Java-RsaDecrypt1">
    <Properties>
      <Property name='action'>decrypt</Property>
      <Property name='decode-source'>base64</Property>
      <Property name='private-key'>{private.my_private_key}</Property>
      <Property name='utf8-decode-result'>true</Property>
    </Properties>
    <ClassName>com.google.apigee.callouts.RsaCrypto</ClassName>
    <ResourceURL>java://apigee-callout-rsa-crypto-20211020.jar</ResourceURL>
  </JavaCallout>
  ```

What will this policy configuration do?:

* the `action` is decrypt, so the policy will decrypt
* No `source` property is specified, therefore this policy will decrypt the message.content.
* Because there is a `decode-source` property, 'base64', the policy will base64-decode the message.content to derive the cipher text.
* There is no `padding` specified, so PKCS1 padding is used.
* The policy will attempt to decoded the cleartext bytes via UTF-8 to produce a plain string. Obviously, this will work only if the original clear text was a plain string encoded with UTF-8.


### Full Properties List

The properties that are common to the RsaCrypto and RsaSigning classes are:

| Property          | Description                                                                                                                                       |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| action            | required. When using RsaCrypto, must be either "decrypt" or "encrypt". When using RsaSigning, must be either "sign" or "verify".                  |
| public-key        | required when action = "encrypt" or "verify". a PEM string representing the public key.                                                           |
| private-key       | required when action = "decrypt" or "sign". a PEM string representing the private key.                                                            |
| private-key-password | optional. a password to use with an encrypted private key.                                                                                     |
| source            | optional. name of the context variable containing the data to encrypt or decrypt, or sign or verify. Do not surround in curly braces. Defaults to `message.content`. |
| decode-source     | optional. one of "base16", "base64", or "base64url", to decode from a string to a octet stream.                                                   |
| debug             | optional. true or false. If true, the policy emits extra context variables. Not for use in production.                                            |
| encode-result     | optional. One of {base16, base64, base64url}. The default is to not encode the result.                                                            |


These are the properties available on the policy when using RsaCrypto (for encryption and decryption):

| Property          | Description                                                                                                                                       |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| padding           | optional. either PKCS1 or OAEP. OAEP implies OAEP with SHA-256 and MGF1 .                                                                         |
| mgf1-hash         | optional. The policy uses SHA256 for the inner hash used by MGF1. Specify one of {SHA1, SHA256, SHA384, SHA512} to override that.                 |
| output            | optional. name of the variable in which to store the output. Defaults to crypto_output.                                                           |
| generate-key      | optional. a boolean. Meaningful only when action = "encrypt". If true, the policy generates a random key of length 128 bits.                      |
| utf8-decode-result| optional. true or false. Applies only when action = decrypt. If true, the policy decodes the byte[] array into a UTF-8 string.                    |

These are the properties available on the policy when using RsaSigning (for signing and verifying):

| Property          | Description                                                                                                                                       |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| padding           | optional. either PSS or PKCS_v1.5.                                                                                                                |
| pss-hash          | optional. The policy uses SHA-256 by default for the PSS hash. You can specify SHA-1 to override that.                                            |
| mgf1-hash         | optional. The policy uses SHA-256 for the Mask generation function (MGF1). Specify one of {SHA1, SHA256, SHA384, SHA512} to override that.        |
| output            | optional. When signing, name of the variable in which to store the output. Defaults to signing_output.                                            |
| signature-source  | required when action = `verify`. This is the name of a variable containing the encoded signature.                                                 |
| decode-signature  | optional when action = `verify`. One of {base16, base64, base64url}. Used to decode the signature.                                                |
| generate-key      | optional. a boolean. Meaningful only when action = "sign". If true, the policy generates a random RSA keypair, signs the payload with the private key, and emits the encoded form of the public and private keys into context variables. |


## Detecting Success and Errors

The policy will return ABORT and set the context variable `crypto_error` if there has been any error at runtime. Your proxy bundles can check this variable in `FaultRules`.

Errors can result at runtime if:

* you do not specify an `action` property, or the `action` is neither `encrypt` nor `decrypt`, nor `sign` nor `verify`
* you pass an invalid string for the public key or private key
* you pass a padding option that is neither OAEP nor PKCS1 when encrypting, or neither PSS nor PKCS_v1.5 when signing.
* you specify `action` = decrypt or verify, and don't supply a `public-key`
* you specify `action` = encrypt or sign, and don't supply a `private-key`
* you use a `decode-*` parameter that is none of {base16, base64, base64url}
* some other configuration value is null or invalid
* you specify `action` = decrypt or verify, and the ciphertext is corrupted
* you specify `action` = encrypt, and the plaintext is more than 245 if you use PKCS1 padding, or more than 214 bytes if you use OAEP padding.

## Building the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is
ready to use, with policy configuration. You need to re-build the jar only if you want
to modify the behavior of the custom policy. Before you do that, be sure you understand
all the configuration options - the policy may be usable for you without modification.

If you do wish to build the jar, you can use [maven](https://maven.apache.org/download.cgi) to do so. The build requires JDK8. Before you run the build the first time, you need to download the Apigee dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests.

If you edit policies offline, copy [the jar file for the custom
policy](callout/target/apigee-callout-rsa-crypto-20211020.jar) to your
apiproxy/resources/java directory.  If you don't edit proxy bundles offline,
upload that jar file into the API Proxy via the Apigee API Proxy Editor .


## Build Dependencies

* Apigee expressions v1.0
* Apigee message-flow v1.0
* Bouncy Castle 1.67

These jars are specified in the pom.xml file.

The first two JARs are builtin to Apigee.

The BouncyCastle jar is available as part of the Apigee runtime, although it is
not a documented part of the Apigee platform and is therefore not guaranteed to
remain available. In the highly unlikely future scenario in which Apigee removes
the BC jar from the Apigee runtime, you could simply upload the BouncyCastle jar
as a resource, either with the apiproxy or with the organization or environment,
to resolve the dependency.


## Author

Dino Chiesa
godino@google.com


## Bugs & Limitations

* When encrypting, does not allow parameterization of the hash function for RSA-OAEP.  Always uses SHA-256.
