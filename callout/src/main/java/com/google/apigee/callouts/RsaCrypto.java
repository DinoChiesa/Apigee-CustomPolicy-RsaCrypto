// RsaCrypto.java
//
// This is the main callout class for the RSA Crypto custom policy for Apigee Edge.
// For full details see the Readme accompanying this source file.
//
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

@IOIntensive
public class RsaCrypto extends RsaBase implements Execution {
  private static final String defaultCipherName = "RSA";
  private static final String defaultCryptoMode =
      "ECB"; // alias: None.  RSA/ECB/PKCS1Padding actually uses no ECB
  private static final String defaultCryptoPadding = "PKCS1Padding";
  private static final Pattern paddingPattern =
      Pattern.compile(
          "^(PKCS1|OAEP|PKCS1Padding|OAEPWithSHA-256AndMGF1Padding)$", Pattern.CASE_INSENSITIVE);
  private static final Pattern fullCipherPattern =
      Pattern.compile(
          "^(RSA)/(None|ECB)/(PKCS1Padding|OAEPWithSHA-256AndMGF1Padding)$",
          Pattern.CASE_INSENSITIVE);
  private static final Pattern cipherNamePattern =
      Pattern.compile("^(RSA)$", Pattern.CASE_INSENSITIVE);
  private static final Pattern modeNamePattern =
      Pattern.compile("^(None|ECB)$", Pattern.CASE_INSENSITIVE);

  public RsaCrypto(Map properties) {
    super(properties);
  }

  enum CryptoAction {
    DECRYPT,
    ENCRYPT
  };

  String getVarPrefix() {
    return "crypto_";
  }

  private EncodingType _getEncodingTypeProperty(MessageContext msgCtxt, String propName)
      throws Exception {
    return EncodingType.valueOf(_getStringProp(msgCtxt, propName, "NONE").toUpperCase());
  }

  private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
    return _getEncodingTypeProperty(msgCtxt, "encode-result");
  }

  private static CryptoAction findByName(String name) {
    for (CryptoAction action : CryptoAction.values()) {
      if (name.equals(action.name())) {
        return action;
      }
    }
    return null;
  }

  private CryptoAction getAction(MessageContext msgCtxt) throws Exception {
    String action = this.properties.get("action");
    if (action != null) action = action.trim();
    if (action == null || action.equals("")) {
      throw new IllegalStateException("specify an action.");
    }
    action = resolveVariableReferences(action, msgCtxt);

    CryptoAction cryptoAction = findByName(action.toUpperCase());
    if (cryptoAction == null) throw new IllegalStateException("specify a valid action.");

    return cryptoAction;
  }

  protected String getMgf1Hash(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "mgf1-hash", defaultMgf1Hash);
  }

  protected static MGF1ParameterSpec getMGF1ParameterSpec(String mgf1Hash) {
    if ((mgf1Hash == null) || mgf1Hash.equals("")) {
      return MGF1ParameterSpec.SHA256;
    }
    return new MGF1ParameterSpec(mgf1Hash.toUpperCase());
  }

  private String getPadding(MessageContext msgCtxt) throws Exception {
    String padding = _getStringProp(msgCtxt, "padding", defaultCryptoPadding);
    Matcher m = paddingPattern.matcher(padding);
    if (!m.matches()) {
      throw new IllegalStateException(String.format("Supplied padding (%s) is invalid.", padding));
    }
    if ("OAEP".equals(padding)) {
      padding = "OAEPWithSHA-256AndMGF1Padding"; // alias
    } else if ("PKCS1".equals(padding)) {
      padding = "PKCS1Padding"; // alias
    }
    return padding;
  }

  private String getMode(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "mode", defaultCryptoMode);
  }

  private String getCipherName(MessageContext msgCtxt) throws Exception {
    String cipher = (String) this.properties.get("cipher");
    if (cipher == null || cipher.equals("")) {
      return defaultCipherName + "/" + getMode(msgCtxt) + "/" + getPadding(msgCtxt);
    }
    cipher = resolveVariableReferences(cipher, msgCtxt);
    if (cipher == null || cipher.equals("")) {
      throw new IllegalStateException("cipher resolves to null or empty.");
    }
    Matcher m = fullCipherPattern.matcher(cipher);
    if (m.matches()) {
      return cipher;
    }

    m = cipherNamePattern.matcher(cipher);
    if (!m.matches()) {
      throw new IllegalStateException("that cipher name is unsupported.");
    }

    // it is a simple algorithm name; apply mode and padding
    cipher += "/" + getMode(msgCtxt) + "/" + getPadding(msgCtxt);
    m = fullCipherPattern.matcher(cipher);
    if (!m.matches()) {
      throw new IllegalStateException("that cipher is unsupported.");
    }
    return cipher;
  }

  private boolean getUtf8DecodeResult(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "utf8-decode-result", false);
  }

  public static byte[] rsaEncrypt(
      String cipherName, PublicKey publicKey, String mgf1Hash, byte[] clearText) throws Exception {
    Cipher cipher = Cipher.getInstance(cipherName);
    String[] parts = cipherName.split("/");
    String padding = parts[2];
    if (padding.equals("OAEPWithSHA-256AndMGF1Padding")) {
      MGF1ParameterSpec mgf1ParamSpec = getMGF1ParameterSpec(mgf1Hash);
      cipher.init(
          Cipher.ENCRYPT_MODE,
          publicKey,
          new OAEPParameterSpec("SHA-256", "MGF1", mgf1ParamSpec, PSource.PSpecified.DEFAULT));
    } else {
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    }
    byte[] cryptoText = cipher.doFinal(clearText);
    return cryptoText;
  }

  public static byte[] rsaDecrypt(
      String cipherName, PrivateKey privateKey, String mgf1Hash, byte[] cipherText)
      throws Exception {
    Cipher cipher = Cipher.getInstance(cipherName);
    String[] parts = cipherName.split("/");
    String padding = parts[2];
    if (padding.equals("OAEPWithSHA-256AndMGF1Padding")) {
      MGF1ParameterSpec mgf1ParamSpec = getMGF1ParameterSpec(mgf1Hash);
      cipher.init(
          Cipher.DECRYPT_MODE,
          privateKey,
          new OAEPParameterSpec("SHA-256", "MGF1", mgf1ParamSpec, PSource.PSpecified.DEFAULT));
    } else {
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
    }
    byte[] clearText = cipher.doFinal(cipherText);
    return clearText;
  }

  private void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("action"));
  }

  private void setOutput(MessageContext msgCtxt, CryptoAction action, byte[] source, byte[] result)
      throws Exception {
    EncodingType outputEncodingWanted = getEncodeResult(msgCtxt);
    String outputVar = getOutputVar(msgCtxt);
    boolean emitGeneratedKey =
        (action == CryptoAction.ENCRYPT) && _getBooleanProperty(msgCtxt, "generate-key", false);

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
      encoder = (a) -> Base64.getUrlEncoder().encodeToString(a);
    } else if (outputEncodingWanted == EncodingType.BASE16) {
      msgCtxt.setVariable(varName("output_encoding"), "base16");
      encoder = (a) -> Base16.encode(a);
    } else {
      throw new IllegalStateException("unhandled encoding");
    }

    msgCtxt.setVariable(outputVar, encoder.apply(result));
    if (emitGeneratedKey) {
      String outputKeyVar = varName("output_key");
      msgCtxt.setVariable(outputKeyVar, encoder.apply(source));
    }
  }

  protected byte[] getSourceBytes(CryptoAction action, MessageContext msgCtxt) throws Exception {
    if (action == CryptoAction.ENCRYPT) {
      boolean wantGenerateKey = _getBooleanProperty(msgCtxt, "generate-key", false);
      if (wantGenerateKey) {
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        return key;
      }
    }

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

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = false;
    try {
      clearVariables(msgCtxt);
      debug = getDebug(msgCtxt);
      String cipherName = getCipherName(msgCtxt);
      msgCtxt.setVariable(varName("cipher"), cipherName);

      CryptoAction action = getAction(msgCtxt); // encrypt or decrypt
      msgCtxt.setVariable(varName("action"), action.name().toLowerCase());

      byte[] source = getSourceBytes(action, msgCtxt);
      byte[] result;

      if (action == CryptoAction.DECRYPT) {
        PrivateKey privateKey = getPrivateKey(msgCtxt);
        result = rsaDecrypt(cipherName, privateKey, getMgf1Hash(msgCtxt), source);

        // try decode into a string from UTF-8
        if (getUtf8DecodeResult(msgCtxt)) {
          msgCtxt.setVariable(getOutputVar(msgCtxt), new String(result, StandardCharsets.UTF_8));
        } else {
          setOutput(msgCtxt, action, source, result);
        }
      } else {
        PublicKey publicKey = getPublicKey(msgCtxt);
        result = rsaEncrypt(cipherName, publicKey, getMgf1Hash(msgCtxt), source);
        setOutput(msgCtxt, action, source, result);
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
