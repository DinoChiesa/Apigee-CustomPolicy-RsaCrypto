# RSA Encryptor and Decryptor sample proxy bundle

This directory contains the configuration for a sample proxy bundle
that shows how to use the Java custom policy for doing RSA Crypto.

## Using the Proxy

Import and deploy the Proxy to your favorite Edge organization + environment.

Open a terminal window, and set the endpoint for your API Proxy:
```
# for Apigee Edge
ORG=my-organization
ENV=test
endpoint=https://${ORG}-${ENV}.apigee.net

# for Apigee X or hybrid
endpoint=https://my-custom-endpoint.net
```

## Encrypt and Decrypt

To encrypt data using a built-in public-key, invoke the proxy like so:

```
curl -i -H 'content-type: text/plain' -X POST \
 "$endpoint/rsa-crypto/encrypt1" \
 -d 'The quick brown fox jumped over the lazy dog.'
```

According to the policy configuration, this request will use PKCS1Padding (the
default), and will encode the result via base64. You will see a result like
this:

```
{
  "ciphertext": "vhjyR5ij0Ua-98AflmYVBmRc7DEqUmBHjZLzavsuR4NIovVUs6ugCpYXsH7XcUSVba4XZmaLqod2FODjWsxnNZAYrPpeW_XIyCUtUhRUWyefgFvlzkSiM-_gLFHoVRUdK6yLIdt9joW_8GU0mXw-MtT5-9J8nBT9i7LnX3aNZyFvhTxLgbCPJXxsfpim3NSAMDKvOlAIyRNZRMoeyN51t39CmQ30Bw3v3cR-cyZenoTgM3rB7NTqwgRe1N0jgJ2lVttGV-Z83SJF_GvqjlY3Q1qldDIbBmLVfcbtaLPquVwojhd1-atup7x3WGpxlCMhBFuP_mujxqT-xwqRtP8FDg==",
  "output_encoding": "base64",
  "cipher": "RSA/ECB/PKCS1Padding",
  "note": "you need the ciphertext, the mode and padding, and a matching key to decrypt."
}


```


To decrypt the encrypted data, invoke the proxy like so:

```
curl -i -H 'content-type: text/plain' -X POST \
 "$endpoint/rsa-crypto/decrypt1" \
 -d 'g2rbpH9qGlxhLueeMxJVDFSpNVPx-OV7VRo1jATP1s5Nc9J4QAOuIMDspAd67r6zaUH67SDnGqEUgGKqeYIQdB8PhrHvKq9EvLezFWeIGjNh2U1VU_UJR4CeV1cnvYDkTWNLnBu882z87JjeFDV5o6MDfIE6QgNpKVqpxO8mwUUDCawZp4AH2GMM6tSjyq7zWmj7KY0evcoOu0woQQuxpyZgSNRoBa7XjKN4rHjSpRFig5cGblQswdYR-d0j06easnIvPSi_RLaR1JZPPG8UgQrn8UKgOezllP4BbfVsTGqJHueimslsdDlGfo87rhy4CijxU5i7ASdxCe09j_TFuw=='

```

According to the policy configuration for _this+ request, the policy will decode
the message.content using base64, then decrypt using the private key, with
RSA/ECB/PKCS1Padding, and then UTF-8 decode the result to produce a string.


You should see an output like this:

```
{
  "output": "The quick brown fox jumped over the lazy dog.",
  "cipher": "RSA/ECB/PKCS1Padding"
}
```

## Encrypt and Decrypt with OAEP

This request uses a different policy configuration:

```
curl -i -X POST $endpoint/rsa-crypto/encrypt2 \
 -d 'cleartext=This policy will use OAEP and MGF1 = SHA=256'
```


To decrypt:

```
curl -i -X POST $endpoint/rsa-crypto/decrypt2 \
 -d 'ciphertext=cae272a5bbd5942cd0f5fa83cbeca2f0a9d38204516dae1ca6fcc3037a546486df32fd189cfe889203b529d7c8fdc12dbea1125b35459d08f77205ee2edb588dcb4664315c1ac31995ec584109b51af8494daf346cbed6db57308502aeb98e15a43dc1c7f0b182f816abb39718966d74184494e3982b61c4cc914867335cb86775002a245fae3fd2464a4baf286924c66665bc1c156ee7bfee26ef6005a93d813db5e23bf97c3e2f162e2661995b3dbc63fc99efa190d930782545e18cc84f79f11b5c50ab13e58a6db6d72597f4e4fae98df121a5f29f7e549a3b7216f18195510e4309fe4bfb7f550337796d49c99acd3e36def3ac1c46f4b5379d5e076540'
```

## Bugs

None?
