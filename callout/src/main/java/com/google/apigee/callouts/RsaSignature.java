// Copyright (c) 2018-2022 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.encoding.Base16;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;

@IOIntensive
public class RsaSignature extends RsaBase implements Execution {
  protected static final String DEFAULT_PRIMARY_HASH = "SHA-256";
  protected static final String DEFAULT_SCHEME = "PKCS1_V1.5";
  protected static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256WithRSA";
  protected static final String DEFAULT_SIGNATURE_PROVIDER = "BC";

  public RsaSignature() {
    super();
  }

  public RsaSignature(Map properties) {
    super(properties);
  }

  enum SignAction {
    SIGN,
    VERIFY
  };

  enum SigningScheme {
    PKCS1V15,
    PSS,
    INVALID,
    NOT_SPECIFIED;

    public static SigningScheme forName(String name) {
      if (name == null) return SigningScheme.NOT_SPECIFIED;
      if ("PSS".equals(name) || "RSASSA-PSS".equals(name)) return SigningScheme.PSS;
      if ("PKCS1V15".equals(name) || "PKCS1_V1.5".equals(name) || "RSASSA-PKCS1-v1_5".equals(name))
        return SigningScheme.PKCS1V15;
      return SigningScheme.INVALID;
    }
  };

  static class HashFunctions {
    public String primary;
    public String mgf1;
  }

  static class SigningConfiguration {
    public SigningScheme scheme;
    public HashFunctions hashes;
    public String signatureProvider;

    public SigningConfiguration() {
      hashes = new HashFunctions();
      scheme = SigningScheme.NOT_SPECIFIED;
    }
  }

  String getVarPrefix() {
    return "signing_";
  }

  private EncodingType _getEncodingTypeProperty(MessageContext msgCtxt, String propName)
      throws Exception {
    return EncodingType.valueOf(_getStringProp(msgCtxt, propName, "NONE").toUpperCase());
  }

  private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
    return _getEncodingTypeProperty(msgCtxt, "encode-result");
  }

  private static SignAction findByName(String name) {
    for (SignAction action : SignAction.values()) {
      if (name.equals(action.name())) {
        return action;
      }
    }
    return null;
  }

  private SignAction getAction(MessageContext msgCtxt) throws Exception {
    String action = this.properties.get("action");
    if (action != null) action = action.trim();
    if (action == null || action.equals("")) {
      throw new IllegalStateException("specify an action.");
    }
    action = resolveVariableReferences(action, msgCtxt);

    SignAction cryptoAction = findByName(action.toUpperCase());
    if (cryptoAction == null) throw new IllegalStateException("specify a valid action.");

    return cryptoAction;
  }

  protected byte[] getSourceBytes(SignAction action, MessageContext msgCtxt) throws Exception {
    Object source1 = msgCtxt.getVariable(getSourceVar());
    if (source1 instanceof byte[]) {
      return (byte[]) source1;
    }

    if (source1 instanceof String) {
      EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-source");
      return decodeString((String) source1, decodingKind);
    }

    // coerce and hope for the best
    return (source1.toString()).getBytes(StandardCharsets.UTF_8);
  }

  protected byte[] getSignatureBytes(MessageContext msgCtxt) throws Exception {
    String signatureVar = _getStringProp(msgCtxt, "signature-source", "signature");
    Object sig = msgCtxt.getVariable(signatureVar);
    if (sig instanceof byte[]) {
      return (byte[]) sig;
    }

    if (sig instanceof String) {
      EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-signature");
      return decodeString((String) sig, decodingKind);
    }

    // coerce and hope for the best
    return (sig.toString()).getBytes(StandardCharsets.UTF_8);
  }

  protected SigningScheme getScheme(MessageContext msgCtxt) throws Exception {
    String schemeString = _getStringProp(msgCtxt, "scheme", DEFAULT_SCHEME);
    SigningScheme scheme = SigningScheme.forName(schemeString.toUpperCase());

    if (scheme == SigningScheme.INVALID) {
      throw new IllegalStateException("unrecognized scheme");
    }

    msgCtxt.setVariable(varName("scheme"), scheme.name());
    return scheme;
  }

  private static Signature getSignatureInstance(SigningConfiguration sigConfig) throws Exception {
    if (sigConfig.scheme == SigningScheme.PKCS1V15) {
      // RSASSA-PKCS1-v1_5
      String signingAlgorithm = sigConfig.hashes.primary.equals("SHA-256") ?
        "SHA256withRSA" : "SHA1withRSA";
      return Signature.getInstance(signingAlgorithm, sigConfig.signatureProvider);
    }

    // RSASSA-PSS
    if (sigConfig.hashes == null) {
      throw new IllegalStateException("missing PSS hashes");
    }
    String signingAlgorithm =
        sigConfig.hashes.primary.equals("SHA-256") ? "SHA256withRSA/PSS" : "SHA1withRSA/PSS";
    Signature signature = Signature.getInstance(signingAlgorithm, sigConfig.signatureProvider);

    MGF1ParameterSpec mgf1pspec = getMGF1ParameterSpec(sigConfig.hashes.mgf1);
    int saltLength =
        (sigConfig.hashes.mgf1.equals("SHA-1"))
            ? 20
            : (sigConfig.hashes.mgf1.equals("SHA-256")) ? 32 : 0;
    int trailer = 1;
    signature.setParameter(
        new PSSParameterSpec(
            sigConfig.hashes.primary, "MGF1", mgf1pspec, saltLength, trailer));
    return signature;
  }

  public static byte[] sign(PrivateKey privateKey, byte[] data, SigningConfiguration sigConfig)
      throws Exception {
    Signature signer = getSignatureInstance(sigConfig);
    signer.initSign(privateKey);
    signer.update(data);
    return signer.sign();
  }

  public static boolean verify(
      PublicKey publicKey, byte[] data, byte[] signature, SigningConfiguration sigConfig)
      throws Exception {
    Signature verifier = getSignatureInstance(sigConfig);
    verifier.initVerify(publicKey);
    verifier.update(data);
    boolean result = verifier.verify(signature);
    return result;
  }

  private void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("action"));
  }

  private void setSignatureOutputVariables(MessageContext msgCtxt, byte[] result) throws Exception {
    EncodingType outputEncodingWanted = getEncodeResult(msgCtxt);
    String outputVar = getOutputVar(msgCtxt);

    Function<byte[], Object> encoder = null;
    if (outputEncodingWanted == EncodingType.NONE) {
      // Emit the result as a Java byte array.
      // Will be retrievable only by another Java callout.
      msgCtxt.setVariable(varName("output_encoding"), "none");
      encoder = (a) -> a; // nop
    } else if (outputEncodingWanted == EncodingType.BASE64) {
      msgCtxt.setVariable(varName("output_encoding"), "base64");
      encoder = (a) -> Base64.getEncoder().encodeToString(a);
    } else if (outputEncodingWanted == EncodingType.BASE64URL) {
      msgCtxt.setVariable(varName("output_encoding"), "base64url");
      encoder = (a) -> Base64.getUrlEncoder().withoutPadding().encodeToString(a);
    } else if (outputEncodingWanted == EncodingType.BASE16) {
      msgCtxt.setVariable(varName("output_encoding"), "base16");
      encoder = (a) -> Base16.encode(a);
    } else {
      throw new IllegalStateException("unhandled encoding");
    }
    msgCtxt.setVariable(outputVar, encoder.apply(result));
  }

  private void emitKeyPair(MessageContext msgCtxt, KeyPair keypair) {
    String privateKeyString =
        "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder().encodeToString(keypair.getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----\n";
    msgCtxt.setVariable(varName("output-privatekey-pem"), privateKeyString);

    String publicKeyString =
        "-----BEGIN PUBLIC KEY-----\n"
            + Base64.getMimeEncoder().encodeToString(keypair.getPublic().getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
    msgCtxt.setVariable(varName("output-publickey-pem"), publicKeyString);
  }

  KeyPair generateKeyPair() throws java.security.NoSuchAlgorithmException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    return kp;
  }

  SigningConfiguration initSigningConfiguration(MessageContext msgCtxt) throws Exception {

    String padding = _getStringProp(msgCtxt, "padding", null);
    if (padding != null) {
      throw new IllegalStateException("padding is not a supported configuration option");
    }

    SigningConfiguration config = new SigningConfiguration();
    config.scheme = getScheme(msgCtxt);

    String primaryHash = _getStringProp(msgCtxt, "primary-hash", DEFAULT_PRIMARY_HASH);

    msgCtxt.setVariable(varName("primary-hash"), primaryHash);
    config.hashes.primary = primaryHash;

    if (config.scheme == SigningScheme.PSS) {
      String mgf1 = getMgf1Hash(msgCtxt, primaryHash);
      msgCtxt.setVariable(varName("mgf1"), mgf1);
      config.hashes.mgf1 = mgf1;
    } else if (config.scheme != SigningScheme.PKCS1V15) {
      throw new IllegalStateException("padding is not a supported configuration option");
    }
    config.signatureProvider =
        _getStringProp(msgCtxt, "signature-provider", DEFAULT_SIGNATURE_PROVIDER);
    return config;
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = false;
    try {
      clearVariables(msgCtxt);
      debug = getDebug(msgCtxt);

      SignAction action = getAction(msgCtxt); // sign or verify
      msgCtxt.setVariable(varName("action"), action.name().toLowerCase());

      SigningConfiguration sigConfig = initSigningConfiguration(msgCtxt);

      byte[] source = getSourceBytes(action, msgCtxt);

      if (action == SignAction.SIGN) {
        boolean wantGenerateKey = _getBooleanProperty(msgCtxt, "generate-key", false);
        KeyPair keypair = null;
        PrivateKey privateKey = null;
        if (wantGenerateKey) {
          keypair = generateKeyPair();
          privateKey = keypair.getPrivate();
        } else {
          privateKey = getPrivateKey(msgCtxt);
        }
        byte[] signature = sign(privateKey, source, sigConfig);
        setSignatureOutputVariables(msgCtxt, signature);
        if (keypair != null) {
          emitKeyPair(msgCtxt, keypair);
        }
      } else {
        msgCtxt.setVariable(varName("verified"), "false");
        PublicKey publicKey = getPublicKey(msgCtxt);
        byte[] signature = getSignatureBytes(msgCtxt);
        boolean verified = verify(publicKey, source, signature, sigConfig);
        msgCtxt.setVariable(varName("verified"), Boolean.toString(verified));
        if (!verified) {
          msgCtxt.setVariable(varName("error"), "verification of the signature failed");
          return ExecutionResult.ABORT;
        }
      }
    } catch (Exception e) {
      if (debug) {
        e.printStackTrace();
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
