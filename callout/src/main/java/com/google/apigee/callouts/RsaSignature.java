// Copyright (c) 2018-2021 Google LLC.
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
  protected static final String defaultPssHash = "SHA-256";
  protected static final String defaultPadding = "PKCS_V1.5";
  public static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256WithRSA";
  public static final String DEFAULT_SIGNATURE_PROVIDER = "BC";

  public RsaSignature(Map properties) {
    super(properties);
  }

  enum SignAction {
    SIGN,
    VERIFY
  };

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

  protected String getPadding(MessageContext msgCtxt) throws Exception {
    String padding = _getStringProp(msgCtxt, "padding", defaultPadding);
    padding = padding.toUpperCase();
    if (!padding.equals("PKCS_V1.5") && !padding.equals("PSS")) {
      throw new IllegalStateException("unrecognized padding");
    }
    msgCtxt.setVariable(varName("padding"), padding);
    return padding;
  }

  class PSSHashes {
    public String primaryHash;
    public String mgf1;

    public PSSHashes(String primaryHash, String mgf1) {
      this.primaryHash = primaryHash;
      this.mgf1 = mgf1;
    }
  }

  protected PSSHashes getPSSHashes(MessageContext msgCtxt) throws Exception {
    String pssHash = _getStringProp(msgCtxt, "pss-hash", defaultPssHash);
    msgCtxt.setVariable(varName("pss-hash"), pssHash);;

    String mgf1Hash = _getStringProp(msgCtxt, "mgf1-hash", pssHash);
    msgCtxt.setVariable(varName("mgf1-hash"), mgf1Hash);;
    return new PSSHashes(pssHash, mgf1Hash);
  }

  private static Signature getSignatureInstance(PSSHashes pssHashes, String signatureAlgorithm, String signatureProvider)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    if (pssHashes == null) {
      return Signature.getInstance(signatureAlgorithm, signatureProvider);
    }
    Signature signature = Signature.getInstance(
                                                pssHashes.primaryHash.equals("SHA-256")?
                                                "SHA256withRSA/PSS" :
                                                "SHA1withRSA/PSS",
                                                signatureProvider);
    //Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");
    MGF1ParameterSpec mgf1pspec = getMGF1ParameterSpec(pssHashes.mgf1);
    int saltLength =
        (pssHashes.mgf1.equals("SHA-1")) ? 20 : (pssHashes.mgf1.equals("SHA-256")) ? 32 : 0;
    int trailer = 1;
    signature.setParameter(
        new PSSParameterSpec(pssHashes.primaryHash, "MGF1", mgf1pspec, saltLength, trailer));
    return signature;
  }

  public static byte[] sign(PrivateKey privateKey, byte[] data, PSSHashes pssHashes, String signatureAlgorithm, String signatureProvider)
      throws Exception {
    Signature signer = getSignatureInstance(pssHashes, signatureAlgorithm, signatureProvider);
    signer.initSign(privateKey);
    signer.update(data);
    return signer.sign();
  }

  public static boolean verify(
          PublicKey publicKey, byte[] data, byte[] signature, PSSHashes pssHashes, String signatureAlgorithm, String signatureProvider) throws Exception {
    Signature verifier = getSignatureInstance(pssHashes, signatureAlgorithm, signatureProvider);
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

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = false;
    try {
      clearVariables(msgCtxt);
      debug = getDebug(msgCtxt);

      SignAction action = getAction(msgCtxt); // sign or verify
      msgCtxt.setVariable(varName("action"), action.name().toLowerCase());

      byte[] source = getSourceBytes(action, msgCtxt);
      String padding = getPadding(msgCtxt);
      PSSHashes pssHashes = (padding.equals("PSS")) ? getPSSHashes(msgCtxt) : null;

      String signatureAlgorithm = _getStringProp(msgCtxt, "signature-algorithm", DEFAULT_SIGNATURE_ALGORITHM);
      String signatureProvider = _getStringProp(msgCtxt, "signature-provider", DEFAULT_SIGNATURE_PROVIDER);

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
        byte[] signature = sign(privateKey, source, pssHashes, signatureAlgorithm, signatureProvider);
        setSignatureOutputVariables(msgCtxt, signature);
        if (keypair != null) {
          emitKeyPair(msgCtxt, keypair);
        }
      } else {
        msgCtxt.setVariable(varName("verified"), "false");
        PublicKey publicKey = getPublicKey(msgCtxt);
        byte[] signature = getSignatureBytes(msgCtxt);
        boolean verified = verify(publicKey, source, signature, pssHashes, signatureAlgorithm, signatureProvider);
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
