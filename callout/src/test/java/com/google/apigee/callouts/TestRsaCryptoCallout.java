// TestRsaCryptoCallout.java
//
// Test code for the AES Crypto custom policy for Apigee Edge. Uses TestNG.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2018-2021 Google LLC
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
// @author: Dino Chiesa
//
// Note:
// If you use the Oracle JDK to run tests, this test, which does
// 256-bit crypto, requires the Unlimited Strength JCE.
//
// Without it, you may get an exception while running this test:
//
// java.security.InvalidKeyException: Illegal key size
//         at javax.crypto.Cipher.checkCryptoPerm(Cipher.java:1039)
//         ....
//
// See http://stackoverflow.com/a/6481658/48082
//
// If you use OpenJDK to run the tests, then it's not an issue.
// In that JDK, there's no restriction on key strength.
//

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.MessageContext;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class TestRsaCryptoCallout {

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  MessageContext msgCtxt;
  ExecutionContext exeCtxt;

  @BeforeMethod()
  public void testSetup1() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map<String, Object> variables;

          public void $init() {
            getVariables();
          }

          private Map<String, Object> getVariables() {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }
            return variables;
          }

          @Mock()
          public Object getVariable(final String name) {
            return getVariables().get(name);
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            getVariables().put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (getVariables().containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();
    System.out.printf("=============================================\n");
  }

  private String privateKey1 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXk9k01JrhGQf1\n"
          + "4B4nymHntaG9SYA2kEQOo/RK4fM2XcebFsSJQ8GgE1AC1GlWU5YzS34WW0w5GMZe\n"
          + "2e2NIGz/x2jeRo9so3hRrQ7/BGl7XnAedEE1P5XmqidQPLRH6B8GoGkw1UifZvXH\n"
          + "kRaKHXSwwJT6uOdS8Fi0IYeZtCVRxk5ltctJZ9Xe6ShFoYbYpX1XbM1daNNmIpIV\n"
          + "EUllJ5bixP6z23BybH5AXrTGSmp7j8O+upqcpvdsoZChWILTCXru/O/5B9ou2S79\n"
          + "YCwF4uYjcMWZdvSfLe4JQJ8JG0eekBTSB+NYGLCRn9HY6Fk5bzvsYZw0wpVOcVPr\n"
          + "3XWAYyJLAgMBAAECggEAPA3692W207hWaF+L5wfRKGyH5yRfrFOaMf3ooye4yk9r\n"
          + "uL+p9pdCjGZ05qTnx123vQht0qqSXGGTeX76V1NOKh8SDsHXWKtdbFtqjw5amDyh\n"
          + "vUojlELnbn++PfL7QgDfC8iKJUl1VrqnA3ZeshEsncS4e/QgtRExlNS2YtI1h0bU\n"
          + "8xaz45QmARgwI/g25gO8hP9iBABk3iNBY96+Kr65ReY8Ivof6Y2yha0ZPEwEfehQ\n"
          + "UxCULh6RDSnUoeOvTu7vxyfb1729PU/0kTr0rRdXIwdvIRqimlLjfm+697dsFvSh\n"
          + "eRK6pKp0GTzxwhkUKck3vAtsRlD+fZIxM2ezMAsg8QKBgQD9WwQL83gE61zDHvvQ\n"
          + "S9LiXmSJGmS9z3KqC5bfVXlCPumf1qWLzZnwa0L6k1wamTVcmOV8zt6uh+Re7dAf\n"
          + "SUz1H8obBpFoemk+v0HDUd4q8Aiqp8wP5rHKYSJbeFIWQPQ/yhZwM3v5iyEN36/X\n"
          + "w+gPHyzRRudbAB9KfzUTyziKeQKBgQDZ0+Ma8AYzgjvZbvCbRiglbg+55rBx38Sm\n"
          + "zgl3Z0OYQnBXCW6rewc/aoSrW6zjZZoaCQ+HWg/rvCk1aDO4mdgi1zXRi531XvE5\n"
          + "IGKAUMxmz6VhFrBhUiU0kA2kZTbKqcCQV2AEcpntiIVQWOxcyxzzbw9nz6YvZyTV\n"
          + "QRCOlOzh4wKBgQCB61Vk54IJS8RyzoWk5+0JZgw5/k3gw+tx5aWFeyhGX0qgS4ry\n"
          + "6Qjir65WHpDhluU1SbaMzOyGJWtnfp32HTmYjaevOiwAnp0vrxYDGg1KiXJ4SLmt\n"
          + "Acj0FeFvdIDrpn1Z5MCi4tPVQJI/shBTHcP3VS4/VxO2p5ZkNl06fEDPSQKBgFqX\n"
          + "fMQfPvT9HNb5BKgPLXMjqvatsoQphCe7WMSH9dzFBOOt0JEQwZrmOfbqUaThBI3/\n"
          + "Zq3sDuMDhj/n7lq/4NvclU1ou3Do43nWtiCXeeroQOd4ADL5bu/FWWcdkQQIRUXC\n"
          + "kPRIlSvss0UPNn4BGzFC5y1NdtgQFYl7Xd9uoHXxAoGATpP/SIufCM3mVCoosSan\n"
          + "ylM0iYCqW+KUhECYlqSqvo7JIfv5tv8qejSi03QS1WHHp8OMqqSfCLEE3tTmcSP1\n"
          + "hHYu+QiRZnABbpD9C1+Akh4dG97Woyfd5igBsT1Ovs9PDCN0rO4I2nJHrNLJSPte\n"
          + "OtpRWoF2/LERvp6RNeXthgs=\n"
          + "-----END PRIVATE KEY-----\n";

  private String publicKey1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA15PZNNSa4RkH9eAeJ8ph\n"
          + "57WhvUmANpBEDqP0SuHzNl3HmxbEiUPBoBNQAtRpVlOWM0t+FltMORjGXtntjSBs\n"
          + "/8do3kaPbKN4Ua0O/wRpe15wHnRBNT+V5qonUDy0R+gfBqBpMNVIn2b1x5EWih10\n"
          + "sMCU+rjnUvBYtCGHmbQlUcZOZbXLSWfV3ukoRaGG2KV9V2zNXWjTZiKSFRFJZSeW\n"
          + "4sT+s9twcmx+QF60xkpqe4/DvrqanKb3bKGQoViC0wl67vzv+QfaLtku/WAsBeLm\n"
          + "I3DFmXb0ny3uCUCfCRtHnpAU0gfjWBiwkZ/R2OhZOW877GGcNMKVTnFT6911gGMi\n"
          + "SwIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  private void reportThings(Map<String, String> props) {
    String test = props.get("testname");
    System.out.println("test  : " + test);
    String cipher = msgCtxt.getVariable("crypto_cipher");
    System.out.println("cipher: " + cipher);
    String action = msgCtxt.getVariable("crypto_action");
    System.out.println("action: " + action);
    String outputEncoding = msgCtxt.getVariable("crypto_output_encoding");
    System.out.println("outputEncoding: " + outputEncoding);
    String output = msgCtxt.getVariable("crypto_output");
    System.out.println("output: " + output);
    String error = msgCtxt.getVariable("crypto_error");
    System.out.println("error : " + error);
  }

  @Test()
  public void encrypt_GenerateKey_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_GenerateKey_Base16");
    properties.put("action", "encrypt");
    properties.put("public-key", publicKey1);
    properties.put("debug", "true");
    properties.put("generate-key", "true");
    properties.put("source", "this-will-not-be-used");
    properties.put("encode-result", "base16");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(error);

    String encodedKey = msgCtxt.getVariable("crypto_output_key");
    Assert.assertNotNull(encodedKey);
  }

  @Test()
  public void encrypt_QuickBrownFox_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_QuickBrownFox_Base16");
    properties.put("action", "encrypt");
    properties.put("public-key", publicKey1);
    properties.put("debug", "true");
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(error);
  }

  @Test()
  public void encrypt_LongMessage_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_LongMessage_Base16");
    properties.put("action", "encrypt");
    properties.put("public-key", publicKey1);
    properties.put("debug", "false");
    properties.put("encode-result", "base16");

    // This will fail.
    // RSA can encrypt messages that are at most several bytes shorter than the modulus of the key pair. The extra bytes are for padding, and the exact number depends on the padding scheme in use.
    // see https://security.stackexchange.com/a/33445/81523

    msgCtxt.setVariable(
        "message.content",
        "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.\n"
            + "Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live. It is altogether fitting and proper that we should do this.\n"
            + "But, in a larger sense, we can not dedicate -- we can not consecrate -- we can not hallow -- this ground. The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us -- that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion -- that we here highly resolve that these dead shall not have died in vain -- that this nation, under God, shall have a new birth of freedom -- and that government of the people, by the people, for the people, shall not perish from the earth.");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertEquals(error, "Data must not be longer than 245 bytes");
  }

  @Test()
  public void encrypt_QuickBrownFox_Base64() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_QuickBrownFox_Base64");
    properties.put("action", "encrypt");
    properties.put("public-key", publicKey1);
    properties.put("debug", "true");
    properties.put("encode-result", "base64");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(error);

    // the output is not predicatable, because randomization.
    //String output = msgCtxt.getVariable("crypto_output");
    // Assert.assertEquals(output, "something"); // NO
  }

  @Test()
  public void decrypt_QuickBrownFox() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt_QuickBrownFox");
    properties.put("action", "decrypt");
    properties.put("decode-source", "base16");
    properties.put("private-key", privateKey1);
    properties.put("utf8-decode-result", "true");
    properties.put("debug", "true");

    msgCtxt.setVariable(
        "message.content",
        "109DC3D8B39E9B4777D2C58A0166C5E5C8F9287E46665FE3B5F015C5D6ABF37A737324CA2ED7C5AD776EF757F6AC40B294F4623279B5E0802BE9ED2A9D87E5583E377F0462F6E229799ED82D928829C2710172E62A8016DE8C4F23956737A5C96DEDA2DED1A00D74B2D4366F0BAA95CB1B04CC4E7F10249E07BC2492DD3D003D93C12C4F6CA8AD28D706712E0C036E01C4A88FF0F601E19811C2202E1F505CCCA55848A246C79FEDA21DDE4E0A54B9C79DAB5D847948635471BA78EAC2973E38C82FA3AED4F8DDCF7DB3DCCD47DDBA770C7032108F393FC905F48584FE1F29578DFD74F3EA1E780079F68D19A7BC6FF98DF69E68F8ACE5DDE690B35D3CAD58B1");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(error);

    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNotNull(output);
    Assert.assertEquals(output, "The quick brown fox jumped over the lazy dog.");
  }

  @Test()
  public void decrypt_QuickBrownFox_BadCipherText() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt_QuickBrownFox_BadCipherText");
    properties.put("action", "decrypt");
    properties.put("decode-source", "base16");
    properties.put("private-key", privateKey1);
    properties.put("utf8-decode-result", "true");
    properties.put("debug", "false");

    // this is not a valid ciphertext
    msgCtxt.setVariable(
        "message.content",
        "7D2C58A0166C5E5C8F9287E46665FE3B5F015C5D6ABF37A737324CA2ED7C5AD776EF757F6AC40B294F4623279B5E0802BE9ED2A9D87E5583E377F0462F6E229799ED82D928829C2710172E62A8016DE8C4F23956737A5C96DEDA2DED1A00D74B2D4366F0BAA95CB1B04CC4E7F10249E07BC2492DD3D003D93C12C4F6CA8AD28D706712E0C036E01Cp4A88FF0F601E19811C2202E1F505CCCA55848A246C79FEDA21DDE4E0A54B9C79DAB5D847948635471BA78EAC2973E38C82FA3AED4F8DDCF7DB3DCCD47DDBA770C7032108F393FC905F48584FE1F29578DFD74F3EA1E780079F68D19A7BC6FF98DF69E68F8ACE");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);
    // retrieve output
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNull(output);
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNotNull(error);
    Assert.assertTrue(error.startsWith("Invalid hexadecimal String supplied."));
  }

  @Test()
  public void encrypt_QuickBrownFox_BadCipher() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_QuickBrownFox_BadCipher");
    properties.put("action", "encrypt");
    properties.put("public-key", privateKey1);
    properties.put("cipher", "RSA/CTR/PKCS1Padding");
    properties.put("debug", "false");

    msgCtxt.setVariable("message.content", "I love APIs");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNotNull(error);
    Assert.assertTrue(error.startsWith("that cipher name is unsupported"));
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNull(output);
  }

  @Test()
  public void Encrypt_QuickBrownFox_BadCipher2() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Encrypt_QuickBrownFox_BadCipher2");
    properties.put("action", "encrypt");
    properties.put("public-key", privateKey1);
    properties.put("cipher", "RSA/ECB/PKCS5Padding");
    properties.put("debug", "false");

    msgCtxt.setVariable("message.content", "I love APIs");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNotNull(error);
    Assert.assertTrue(error.startsWith("that cipher name is unsupported"));
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNull(output);
  }

  @Test()
  public void Encrypt_QuickBrownFox_BadAction() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Encrypt_QuickBrownFox_BadAction");
    properties.put("action", "transform");
    properties.put("public-key", privateKey1);
    properties.put("cipher", "RSA/None/PKCS1Padding");
    properties.put("debug", "false");

    msgCtxt.setVariable("message.content", "I love APIs");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "specify a valid action.");
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNull(output);
  }

  @Test()
  public void Encrypt_QuickBrownFox_BadKey() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Encrypt_QuickBrownFox_BadKey");
    properties.put("action", "encrypt");
    properties.put("public-key", privateKey1);
    properties.put("cipher", "RSA/None/PKCS1Padding");
    properties.put("debug", "false");

    msgCtxt.setVariable("message.content", "I love APIs");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "that does not appear to be a public key.");
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNull(output);
  }

  @Test()
  public void Decrypt_QuickBrownFox_BadKey() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Decrypt_QuickBrownFox_BadKey");
    properties.put("action", "decrypt");
    properties.put("decode-source", "base16");
    properties.put("private-key", publicKey1);
    properties.put("utf8-decode-result", "true");
    properties.put("debug", "false");

    msgCtxt.setVariable(
        "message.content",
        "109DC3D8B39E9B4777D2C58A0166C5E5C8F9287E46665FE3B5F015C5D6ABF37A737324CA2ED7C5AD776EF757F6AC40B294F4623279B5E0802BE9ED2A9D87E5583E377F0462F6E229799ED82D928829C2710172E62A8016DE8C4F23956737A5C96DEDA2DED1A00D74B2D4366F0BAA95CB1B04CC4E7F10249E07BC2492DD3D003D93C12C4F6CA8AD28D706712E0C036E01C4A88FF0F601E19811C2202E1F505CCCA55848A246C79FEDA21DDE4E0A54B9C79DAB5D847948635471BA78EAC2973E38C82FA3AED4F8DDCF7DB3DCCD47DDBA770C7032108F393FC905F48584FE1F29578DFD74F3EA1E780079F68D19A7BC6FF98DF69E68F8ACE5DDE690B35D3CAD58B1");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertEquals(error, "Didn't find OpenSSL key. Found: org.bouncycastle.asn1.x509.SubjectPublicKeyInfo");
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNull(output);
  }

  @Test()
  public void decrypt_QuickBrownFox_MissingKey() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt_QuickBrownFox_MissingKey");
    properties.put("action", "decrypt");
    properties.put("decode-source", "base16");
    properties.put("private-key", "");
    properties.put("utf8-decode-result", "true");
    properties.put("debug", "false");

    msgCtxt.setVariable(
        "message.content",
        "109DC3D8B39E9B4777D2C58A0166C5E5C8F9287E46665FE3B5F015C5D6ABF37A737324CA2ED7C5AD776EF757F6AC40B294F4623279B5E0802BE9ED2A9D87E5583E377F0462F6E229799ED82D928829C2710172E62A8016DE8C4F23956737A5C96DEDA2DED1A00D74B2D4366F0BAA95CB1B04CC4E7F10249E07BC2492DD3D003D93C12C4F6CA8AD28D706712E0C036E01C4A88FF0F601E19811C2202E1F505CCCA55848A246C79FEDA21DDE4E0A54B9C79DAB5D847948635471BA78EAC2973E38C82FA3AED4F8DDCF7DB3DCCD47DDBA770C7032108F393FC905F48584FE1F29578DFD74F3EA1E780079F68D19A7BC6FF98DF69E68F8ACE5DDE690B35D3CAD58B1");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);
    // retrieve output
    String output = msgCtxt.getVariable("crypto_output");
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(output);
    Assert.assertEquals(error, "private-key resolves to null or empty.");
  }


  @Test()
  public void encrypt_QuickBrownFox_MissingKey() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_QuickBrownFox_MissingKey");
    properties.put("action", "encrypt");
    properties.put("public-key", "");
    properties.put("debug", "false");
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertEquals(error, "public-key resolves to null or empty.");
  }

  @Test()
  public void encrypt_QuickBrownFox_OAEP() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_QuickBrownFox_OAEP");
    properties.put("action", "encrypt");
    properties.put("cipher", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    properties.put("public-key", publicKey1);
    properties.put("debug", "false");
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String output = msgCtxt.getVariable("crypto_output");
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNotNull(output);
    Assert.assertNull(error);
  }

  @Test()
  public void encrypt_QuickBrownFox_OAEP2() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_QuickBrownFox_OAEP2");
    properties.put("action", "encrypt");
    properties.put("padding", "OAEP");
    properties.put("public-key", publicKey1);
    properties.put("debug", "false");
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void Encrypt_QuickBrownFox_PKCS1Padding_ExplicitMGF1_Hash_SHA256() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Encrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash_SHA256");
    properties.put("action", "encrypt");
    properties.put("padding", "PKCS1Padding");
    properties.put("public-key", publicKey1);
    properties.put("mgf1-hash", "SHA-256");
    properties.put("debug", "false");
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void Encrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash_SHA1() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Encrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash_SHA1");
    properties.put("action", "encrypt");
    properties.put("padding", "OAEP");
    properties.put("public-key", publicKey1);
    properties.put("mgf1-hash", "SHA-1");
    properties.put("debug", "false");
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void Decrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Decrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash");
    properties.put("action", "decrypt");
    properties.put("padding", "OAEP");
    properties.put("mgf1-hash", "SHA-256");
    properties.put("decode-source", "base16");
    properties.put("private-key", privateKey1);
    properties.put("utf8-decode-result", "true");
    properties.put("debug", "false");

    msgCtxt.setVariable(
        "message.content",
        "71E11184847A41DAE391FDAA12D8B0EF2F84E104B6B4541C3428E3820F2E20F0892F5ADF2E2979850E5BD06BAC054BA062B0309977FB2979B524D48784E4F193294EEDA8214E3B5D0F2AA636CAA84579F78F6551E7115FA43A80FF457BA0651CB989C81512E2BD6034037FAAF9C49620E7729070FFB2DA820790CE0318DDD67A03466304D1FA1DDECBB08DC81913D560098822BFF8D4EACC421EE8D2EF65670393BBE123A00B4DFA623508C05016617380FDDFC7D02FD532BF616F01A9C6059D4FA7C87AE4D0BA748352DBAABEC099E6A65D9E493A79338E61203EFA6745E08181F182F8F7FD135F34B2FEA505E023056D48A305CD44A156B9A453CAE23E2762");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNull(error);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    reportThings(properties);

    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void Decrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash_MismatchSHA1() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Decrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash_MismatchSHA1");
    properties.put("action", "decrypt");
    properties.put("padding", "OAEP");
    properties.put("mgf1-hash", "SHA-1"); // was encrypted with SHA-256
    properties.put("decode-source", "base16");
    properties.put("private-key", privateKey1);
    properties.put("utf8-decode-result", "true");
    properties.put("debug", "false");

    msgCtxt.setVariable(
        "message.content",
        "71E11184847A41DAE391FDAA12D8B0EF2F84E104B6B4541C3428E3820F2E20F0892F5ADF2E2979850E5BD06BAC054BA062B0309977FB2979B524D48784E4F193294EEDA8214E3B5D0F2AA636CAA84579F78F6551E7115FA43A80FF457BA0651CB989C81512E2BD6034037FAAF9C49620E7729070FFB2DA820790CE0318DDD67A03466304D1FA1DDECBB08DC81913D560098822BFF8D4EACC421EE8D2EF65670393BBE123A00B4DFA623508C05016617380FDDFC7D02FD532BF616F01A9C6059D4FA7C87AE4D0BA748352DBAABEC099E6A65D9E493A79338E61203EFA6745E08181F182F8F7FD135F34B2FEA505E023056D48A305CD44A156B9A453CAE23E2762");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);

    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "Decryption error");
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNull(output);
  }

  @Test()
  public void Decrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash_MismatchSHA256() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "Decrypt_QuickBrownFox_OAEP2_ExplicitMGF1_Hash_MismatchSHA256");
    properties.put("action", "decrypt");
    properties.put("padding", "OAEP");
    properties.put("mgf1-hash", "SHA-256"); // was encrypted with SHA-1
    properties.put("decode-source", "base16");
    properties.put("private-key", privateKey1);
    properties.put("utf8-decode-result", "true");
    properties.put("debug", "false");

    msgCtxt.setVariable(
        "message.content",
        "AB7430D5A701DCF7BADEC24AD647186E326B61A3F739D64CF05455144F3202020AC16049152B95E16F9A8B9C46E09F156A3FAAB92EF3BA805089B79D76365E3C387A4AA84DB71168FF49E615CB3FE13E120A9330441E445C0ADFDAFB343B3E6C6DD69EEC446203DE3EF92F2F77B0E9FAE375F8B08821A846F034B44599EDF5614CDE33D988D423FC84122F87BA61797BC002BABC842E48FC2DAA906B6586575C01557BFC790DCBC4A23D33101594ED5D8765AA23272AE4558A9C545D390594A9CB0E92D22722FF9DB66E7DBA5879E27BD53D09F4DC86338971C7CA24A663D5E078C55F85F728D4A188496706BCE408F7FE60360C61FCEDE875DF7718333B88BC");

    RsaCryptoCallout callout = new RsaCryptoCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    reportThings(properties);

    // retrieve output
    String error = msgCtxt.getVariable("crypto_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "Decryption error");
    String output = msgCtxt.getVariable("crypto_output");
    Assert.assertNull(output);
  }
}
