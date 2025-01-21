// Copyright (c) 2018-2025 Google LLC
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

import com.apigee.flow.execution.ExecutionResult;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestRsaSignature extends TestRsaBase {

  private void reportThings(Map<String, String> props) {
    String test = props.get("testname");
    System.out.println("test  : " + test);
    String action = msgCtxt.getVariable("signing_action");
    System.out.println("action: " + action);
    String outputEncoding = msgCtxt.getVariable("signing_output_encoding");
    System.out.println("outputEncoding: " + outputEncoding);
    Object output =
        msgCtxt.getVariable(action.equals("sign") ? "signing_output" : "signing_verified");
    System.out.println("output: " + output.toString());

    String error = msgCtxt.getVariable("signing_error");
    System.out.println("error : " + error);
  }

  @DataProvider(name = "output-encodings")
  public Object[][] dataProviderMethod1() {
    return new Object[][] {{"base16"}, {"base64"}, {"base64url"}, {"none"}};
  }

  @Test(dataProvider = "output-encodings")
  public void sign_GenerateKey(String outputEncoding) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_GenerateKey");
    properties.put("action", "sign");
    properties.put("generate-key", "true");
    properties.put("debug", "true");
    properties.put("encode-result", outputEncoding);
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNull(error);

    String encodedPublicKey = msgCtxt.getVariable("signing_output-publickey-pem");
    Assert.assertNotNull(encodedPublicKey);
    String encodedPrivateKey = msgCtxt.getVariable("signing_output-privatekey-pem");
    Assert.assertNotNull(encodedPrivateKey);
    System.out.println("publickey: " + encodedPublicKey);
  }

  @Test(dataProvider = "output-encodings")
  public void sign_ProvidedKey(String outputEncoding) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_ProvidedKey");
    properties.put("action", "sign");
    properties.put("private-key", privateKey1);
    properties.put("debug", "true");
    properties.put("encode-result", outputEncoding);
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNull(error);

    String encodedPublicKey = msgCtxt.getVariable("signing_output-publickey-pem");
    Assert.assertNull(encodedPublicKey);
    String encodedPrivateKey = msgCtxt.getVariable("signing_output-privatekey-pem");
    Assert.assertNull(encodedPrivateKey);
  }

  @Test(dataProvider = "output-encodings")
  public void sign_ProvidedKey_ProvidedSignatureMethod(String outputEncoding) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_ProvidedKey");
    properties.put("action", "sign");
    properties.put("private-key", privateKey1);
    properties.put("debug", "true");
    properties.put("encode-result", outputEncoding);
    properties.put("signature-algorithm", "SHA1withRSA");
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNull(error);

    String encodedPublicKey = msgCtxt.getVariable("signing_output-publickey-pem");
    Assert.assertNull(encodedPublicKey);
    String encodedPrivateKey = msgCtxt.getVariable("signing_output-privatekey-pem");
    Assert.assertNull(encodedPrivateKey);
  }

  @Test(dataProvider = "output-encodings")
  public void sign_PSS_ProvidedKey(String outputEncoding) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_PSS_ProvidedKey");
    properties.put("action", "sign");
    properties.put("scheme", "PSS");
    properties.put("private-key", privateKey1);
    properties.put("debug", "true");
    properties.put("encode-result", outputEncoding);
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNull(error);
    Object output = msgCtxt.getVariable("signing_output");
    Assert.assertNotNull(output);
  }

  @Test(dataProvider = "pkcs-v1_5-signature-encodings")
  public void verify_ProvidedKey(String encodedSignature, String encoding) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_ProvidedKey");
    properties.put("action", "verify");
    properties.put("signature-source", "sigvar");
    properties.put("decode-signature", encoding);
    properties.put("public-key", publicKey1);
    properties.put("debug", "true");
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");
    msgCtxt.setVariable("sigvar", encodedSignature);

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNull(error);

    String encodedPublicKey = msgCtxt.getVariable("signing_output-publickey-pem");
    Assert.assertNull(encodedPublicKey);
    String encodedPrivateKey = msgCtxt.getVariable("signing_output-privatekey-pem");
    Assert.assertNull(encodedPrivateKey);

    String verificationOk = msgCtxt.getVariable("signing_verified");
    Assert.assertNotNull(verificationOk);
    Assert.assertEquals(verificationOk.toLowerCase(), "true");
  }

  @DataProvider(name = "pkcs-v1_5-signature-encodings")
  public Object[][] dataProviderMethod2() {
    final String base16Signature =
        "000f3f4335a96a23e729d260d118c7a4c8b21962899ce96e649fa6fda813d643"
            + "c62cc917e777e308ce9b801ae4a904708b47053a9fbb12624923f3c1c2e1e1f0"
            + "225182feb82d6a9e6f37d16e7a635b51a04d6928dbd5244fc5fd5b8722f7607c"
            + "34f2eedca173eb1713456f51885aef36aac70f3886c502fad59e92e2cc332dbd"
            + "1addd2aea21106ba8a9ac2434db07f49a257f543182250381017a68f407a8f19"
            + "254c49406d24ca94fd41a91b9ba606189e5172bb5913e1f5846f0bc1979f4097"
            + "b8c5cde44bc34e3e2ef9ab0e60703ec6c518b36c47845e7aa2b7344b3a219dd8"
            + "4eb1a08cf695422e7a669c03ceda73ff67c919ed79ea82cd52a9a2244d935f75";

    final String base64Signature =
        "AA8/QzWpaiPnKdJg0RjHpMiyGWKJnOluZJ+m/agT1kPGLMkX53fjCM6bgBrkqQRw"
            + "i0cFOp+7EmJJI/PBwuHh8CJRgv64LWqebzfRbnpjW1GgTWko29UkT8X9W4ci92B8"
            + "NPLu3KFz6xcTRW9RiFrvNqrHDziGxQL61Z6S4swzLb0a3dKuohEGuoqawkNNsH9J"
            + "olf1QxgiUDgQF6aPQHqPGSVMSUBtJMqU/UGpG5umBhieUXK7WRPh9YRvC8GXn0CX"
            + "uMXN5EvDTj4u+asOYHA+xsUYs2xHhF56orc0SzohndhOsaCM9pVCLnpmnAPO2nP/"
            + "Z8kZ7Xnqgs1SqaIkTZNfdQ==";

    final String base64UrlSignature =
        "AA8_QzWpaiPnKdJg0RjHpMiyGWKJnOluZJ-m_agT1kPGLMkX53fjCM6bgBrkqQRw"
            + "i0cFOp-7EmJJI_PBwuHh8CJRgv64LWqebzfRbnpjW1GgTWko29UkT8X9W4ci92B8"
            + "NPLu3KFz6xcTRW9RiFrvNqrHDziGxQL61Z6S4swzLb0a3dKuohEGuoqawkNNsH9J"
            + "olf1QxgiUDgQF6aPQHqPGSVMSUBtJMqU_UGpG5umBhieUXK7WRPh9YRvC8GXn0CX"
            + "uMXN5EvDTj4u-asOYHA-xsUYs2xHhF56orc0SzohndhOsaCM9pVCLnpmnAPO2nP_"
            + "Z8kZ7Xnqgs1SqaIkTZNfdQ";

    return new Object[][] {
      {base16Signature, "base16"},
      {base64Signature, "base64"},
      {base64UrlSignature, "base64url"}
    };
  }

  @Test(dataProvider = "pss-signature-encodings")
  public void verify_PSS_ProvidedKey(String encodedSignature, String encoding) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_PSS_ProvidedKey");
    properties.put("action", "verify");
    properties.put("scheme", "PSS"); // alias of RSASSA-PSS
    properties.put("signature-source", "sigvar");
    properties.put("decode-signature", encoding);
    properties.put("public-key", publicKey1);
    properties.put("debug", "true");
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");
    msgCtxt.setVariable("sigvar", encodedSignature);

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNull(error);

    String verificationOk = msgCtxt.getVariable("signing_verified");
    Assert.assertNotNull(verificationOk);
    Assert.assertEquals(verificationOk.toLowerCase(), "true");
  }

  @Test(dataProvider = "pss-signature-encodings")
  public void verify_RSASSA_PSS_ProvidedKey(String encodedSignature, String encoding) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_RSASSA_PSS_ProvidedKey");
    properties.put("action", "verify");
    properties.put("scheme", "RSASSA-PSS");
    properties.put("signature-source", "sigvar");
    properties.put("decode-signature", encoding);
    properties.put("public-key", publicKey1);
    properties.put("debug", "true");
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");
    msgCtxt.setVariable("sigvar", encodedSignature);

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNull(error);

    String verificationOk = msgCtxt.getVariable("signing_verified");
    Assert.assertNotNull(verificationOk);
    Assert.assertEquals(verificationOk.toLowerCase(), "true");
  }

  @Test(dataProvider = "pss-signature-encodings")
  public void verify_PSS_ProvidedKey_Wrong_Hash(String encodedSignature, String encoding) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_PSS_ProvidedKey_Wrong_Hash");
    properties.put("action", "verify");
    properties.put("scheme", "PSS");
    properties.put("primary-hash", "SHA-1");
    properties.put("signature-source", "sigvar");
    properties.put("decode-signature", encoding);
    properties.put("public-key", publicKey1);
    properties.put("debug", "false");
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");
    msgCtxt.setVariable("sigvar", encodedSignature);

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "verification of the signature failed");

    String verificationOk = msgCtxt.getVariable("signing_verified");
    Assert.assertNotNull(verificationOk);
    Assert.assertEquals(verificationOk.toLowerCase(), "false");
  }

  @DataProvider(name = "pss-signature-encodings")
  public Object[][] dataProviderMethod3() {
    final String base16Signature =
        "77c1ac4f797616b9d7dd26edc835d238a9ea33d77fa4386923b918a19ff87385"
            + "879366f607c75ccbd6d6b96a799c81370dc3105f6adefb936e8710098eed42cf"
            + "88b2c82465ce00b3f15ec90a6cfc32f231a9fd1c409a0ec84817d5ab11535234"
            + "556c2b7691b88645085e3f32d987e1d66d7c2e3d20152228937d0820921da61e"
            + "858a33b3a40cd9a9e3c23b583c481b2821c4a3ed9e0293b6750181b4bb1a2d9a"
            + "69eda987863b192248710852889e43d2c64b04bef71729a1d2b2cb65370dd006"
            + "eb7eaa4e4b07f8a25e805d9311acc996e9b3fd80fa0f41622f1257bed1c62d90"
            + "a9cccff8ee7bd9d035b5af5c40a2f2bac6d35138ad01ea3631bf723c17997fd8";

    final String base64Signature =
        "RvRD/NSGMlybKwhn1BskB7wlEZ/g9M4Z6h6YNB96Ws4gmLWamdUJD3xS/+qMztvv"
            + "OelbvR6QTuvx6IESfXK27Tyb+VfmBCGrRlJ9HvkR4lmQsy+e5y3jGCY5Y5y2SX+r"
            + "YfAuKNzDs6jAoa1BN2TSSffYvsJxd4Xrh26V9GhJJkH5zDIYDV7wxkImgIZSAA1f"
            + "q05g/4NpGlNz4rOPnCHsEsPbjuwDWvE9lcGEC9+LJ7VpsMqBJ/+frkSI+4lB9Zw0"
            + "N5P/JWgK1XCIDHApNVQ6ePkwexqb9QHQYX8DK2TdG92ZgI2tZP9y0hNj6dOdFA1d"
            + "7xskwvxOEIxHWKFeLt2I6g==";

    final String base64UrlSignature =
        "uM59y8-HV1Pmi9i7rrJZs-NK4G0I4utRg6hvYjFi0hIkGgGnL1EEMO7wHKaWVD9y"
            + "OVIZpJY7j-rpSu8bPpvUObS5OqFq1WoSVA33PV0T20NAJiS988WNC4ZB1qnveZIP"
            + "2bF_JFtxC0ElcqRQtfgk9983NAXghyMGGoVUsd9s0-Rkj2pUSI03StEKcypgfhql"
            + "xF43ZX7a4MFIjbToq-qRh_isou-K7IG8cW_bt3JFtbTxas9f-SLLCN_bA8ixNVJR"
            + "LgucgxMnEmiOouQ2cXNWfqMUTf1T77SSwyuz8Rn4_zxXA7XzTlp-iohKAChicGEA"
            + "MLzLLWTXJD5ivbzXGIC9ng";

    return new Object[][] {
      {base16Signature, "base16"},
      {base64Signature, "base64"},
      {base64UrlSignature, "base64url"}
    };
  }

  @Test
  public void verify_PSS_ProvidedKey_Inconsistent_Input() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_PSS_ProvidedKey_Inconsistent_Input");
    properties.put("action", "verify");
    properties.put("scheme", "PSS");
    properties.put("primary-hash", "SHA-256");
    properties.put("mgf1-hash", "SHA-1");
    properties.put("signature-source", "sigvar");
    properties.put("decode-signature", "base64url");
    properties.put("public-key", publicKey1);
    properties.put("debug", "false");
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");
    msgCtxt.setVariable("sigvar", "does-not-matter");

    RsaSignature callout = new RsaSignature(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    String error = msgCtxt.getVariable("signing_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(
        error, "digest algorithm for MGF should be the same as for PSS parameters.");

    String verificationOk = msgCtxt.getVariable("signing_verified");
    Assert.assertNotNull(verificationOk);
    Assert.assertEquals(verificationOk.toLowerCase(), "false");
  }
}
