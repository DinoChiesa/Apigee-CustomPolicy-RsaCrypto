# RSA Crypto callout

This directory contains the Java source code for
a Java callout for Apigee Edge that performs RSA Encryption and Decryption of
data or message payloads.

RSA can encrypt only small payloads - RSA, as defined by PKCS#1,
can be used to encrypt messages of limited size. For example, with the commonly used "v1.5
padding" and a 2048-bit RSA key, the maximum size of data which can be
encrypted with RSA is 245 bytes. ([cite](https://security.stackexchange.com/a/33445/81523))
For OAEP, it is 214 bytes.

This may seem to be a severe limitation. But, it may be useful to use RSA
encryption to encrypt a symmetric key, and then use that symmetric key to
AES-encrypt a larger message. This is a common pattern and is used in TLS,
encrypted JWT, PGP, S/MIME, and many other security protocols.

The general pattern is:

- generate a random AES key,
- encrypt the plaintext with that key using AES with some specific mode
- encrypt the AES key with RSA
- concatenate those ciphertexts in some way in the output stream.

This callout just does the 3rd part there: it encrypts a small message (which
might be used as an AES key). It can also do the converse: decrypt the small message.


One possible use of this policy: as part of a flow which parses an encrypted JWT. 

## License

This code is Copyright (c) 2017-2019 Google LLC, and is released under the Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Using the Custom Policy

You do not need to build the Jar in order to use the custom policy.

When you use the policy to encrypt data, the resulting cipher-text can be
decrypted by other systems. Likewise, the policy can decrypt cipher-text
obtained from other systems.  To do that, the encrypting and decrypting systems
need to use a matched key pair (public and private), the same padding (either
PKCS1 or OAEP).

The policy performs only RSA crypto.


## Policy Configuration

There are a variety of options, which you can select using Properties in the configuration. Examples follow, but here's a quick summary:

- the policy uses as its source, the message.content. If you wish to encrypt something else, specify it with the source property
- The policy always uses ECB, which is sort of a misnomer since it's a single block encryption.
- when using OAEP padding, the policy uses SHA-256 as the MGF1 hash. You can specify this with the mgf1-hash property.
- you can optionally encode (base64, base64url, base16) the output octet stream upon encryption
- you can optionally UTF-8 decode the output octet stream upon decryption


## Example: Basic Encryption with Numerous Defaults

  ```xml
  <JavaCallout name="Java-RsaEncrypt1">
    <Properties>
      <Property name='action'>encrypt</Property>
      <Property name='public-key>{my_public_key}</Property>
      <Property name='encode-result'>base64</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.RsaCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-rsa-crypto-20191101.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this policy configuration:

* the action is encrypt, so the policy will encrypt
* No source property is specified, therefore this policy will encrypt the message.content.
* The public key will be deserialized from the PEM string in the variable `my_public_key`
* There is no mode specified, so ECB is used.
* There is no padding specified, so PKCS1Padding is used.
* The resulting ciphertext is encoded via base64, and stored into crypto_output (the default).

To decrypt the resulting ciphertext, either within Apigee with this policy, or
using some other system, the decryptor needs to use the corresponding private
key, and the same mode and padding.


### Example: Basic Decryption

  ```xml
  <JavaCallout name="Java-AesDecrypt1">
    <Properties>
      <Property name='action'>decrypt</Property>
      <Property name='decode-source'>base64</Property>
      <Property name='private-key>{private.my_private_key}</Property>
      <Property name='utf8-decode-result'>true</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.RsasCryptoCallout</ClassName>
    <ResourceURL>java://edge-callout-rsa-crypto-20191101.jar</ResourceURL>
  </JavaCallout>
  ```

What will this policy configuration do?:

* the action is decrypt, so the policy will decrypt
* No source property is specified, therefore this policy will decrypt the message.content.
* Because there is a decode-source property, 'base64', the policy will base64-decode the message.content to derive the cipher text.
* There is no mode or padding specified, so RSA/ECB/PKCS5Padding is used.
* The result is decoded via UTF-8 to produce a plain string. Obviously, this will work only if the original clear text was a plain string.


### Full Properties List

These are the properties available on the policy:

| Property          | Description                                                                                                                                       |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| action            | required. either "decrypt" or "encrypt".                                                                                                          |
| public-key        | required when action = "encrypt". a PEM string representing the public key.                                                                       |
| private-key       | required when action = "decrypt". a PEM string representing the private key.                                                                      |
| private-key-password | optional. a password to use with an encrypted private key.                                                                                     |
| source            | optional. name of the context variable containing the data to encrypt or decrypt. Do not surround in curly braces. Defaults to `message.content`. |
| decode-source     | optional. either "base16" or "base64", to decode from a string to a octet stream.                                                                 |
| mode              | optional. You probably don't want to use this. It defaults to ECB. Probably meaningless with rSA crypto.                                          |
| padding           | optional. either PKCS1Padding or OAEP.  OAEP implies (is an alias of) OAEPWithSHA-256AndMGF1Padding.                                              |
| output            | optional. name of the variable in which to store the output. Defaults to crypto_output.                                                           |
| encode-result     | optional. One of {base16, base64, base64url}. The default is to not encode the result.                                                            |
| utf8-decode-result| optional. true or false. Applies only when action = decrypt. Decodes the byte[] array into a UTF-8 string.                                        |
| debug             | optional. true or false. Emits extra context variables if true. Not for use in production.                                                        |



## Detecting Success and Errors

The policy will return ABORT and set the context variable `crypto_error` if there has been any error at runtime. Your proxy bundles can check this variable in `FaultRules`.

Errors can result at runtime if:

* you do not specify an `action` property, or the `action` is neither `encrypt` nor `decrypt`
* you pass an invalid string for the public key or private key
* you pass a padding option that is not supported.
* you specify `action` = decrypt, and don't supply a `public-key`
* you specify `action` = encrypt, and don't supply a `private-key`
* you use a `decode-*` parameter that is neither base16 nor base64
* some other configuration value is null or invalid
* you specify `action` = decrypt, and the ciphertext is corrupted
* you specify `action` = encrypt, and the plaintext is more than 245 or 214 bytes (depending on the padding you chose)

## Building the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is
ready to use, with policy configuration. You need to re-build the jar only if you want
to modify the behavior of the custom policy. Before you do that, be sure you understand
all the configuration options - the policy may be usable for you without modification.

If you do wish to build the jar, you can use [maven](https://maven.apache.org/download.cgi) to do so. The build requires JDK8. Before you run the build the first time, you need to download the Apigee Edge dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests.

If you edit policies offline, copy [the jar file for the custom policy](callout/target/edge-callout-rsa-crypto-20191101.jar)  to your apiproxy/resources/java directory.  If you don't edit proxy bundles offline, upload that jar file into the API Proxy via the Edge API Proxy Editor .


## Build Dependencies

* Apigee Edge expressions v1.0
* Apigee Edge message-flow v1.0
* Bouncy Castle 1.62

These jars are specified in the pom.xml file.

You do not need to upload any of these Jars to Apigee Edge with your policy.  They are all available in Apigee Edge already.

## Author

Dino Chiesa
godino@google.com
