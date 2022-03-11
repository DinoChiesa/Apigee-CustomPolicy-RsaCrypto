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

import com.apigee.flow.message.MessageContext;
import com.google.apigee.encoding.Base16;
import com.google.apigee.util.CalloutUtil;
import com.google.apigee.util.KeyUtil;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class RsaBase {
  protected static final String defaultOutputVarSuffix = "output";
  protected static final String TRUE = "true";
  protected static final String DEFAULT_MGF1_HASH = "SHA-256";
  private static final Pattern variableReferencePattern =
      Pattern.compile("(.*?)\\{([^\\{\\} :][^\\{\\} ]*?)\\}(.*?)");
  private static final Pattern commonErrorPattern = Pattern.compile("^(.+?)[:;] (.+)$");

  protected static final SecureRandom secureRandom = new SecureRandom();

  enum EncodingType {
    NONE,
    BASE64,
    BASE64URL,
    BASE16
  };

  protected final Map<String, String> properties;

  public RsaBase(Map properties) {
    this.properties = CalloutUtil.genericizeMap(properties);
  }

  abstract String getVarPrefix();

  protected String varName(String s) {
    return getVarPrefix() + s;
  }

  protected String resolveVariableReferences(String spec, MessageContext msgCtxt) {
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      String ref = matcher.group(2);
      String[] parts = ref.split(":", 2);
      Object v = msgCtxt.getVariable(parts[0]);
      if (v != null) {
        sb.append((String) v);
      } else if (parts.length > 1) {
        sb.append(parts[1]);
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  protected String getSourceVar() {
    String source = this.properties.get("source");
    if (source == null || source.equals("")) {
      // by default, get the content of the message (either request
      // or response)
      return "message.content";
    }
    return source;
  }

  protected String _getStringProp(MessageContext msgCtxt, String name, String defaultValue)
      throws Exception {
    String value = this.properties.get(name);
    if (value != null) value = value.trim();
    if (value == null || value.equals("")) {
      return defaultValue;
    }
    value = resolveVariableReferences(value, msgCtxt);
    if (value == null || value.equals("")) {
      throw new IllegalStateException(name + " resolves to null or empty.");
    }
    return value;
  }

  protected String getOutputVar(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "output", varName(defaultOutputVarSuffix));
  }

  private EncodingType _getEncodingTypeProperty(MessageContext msgCtxt, String propName)
      throws Exception {
    return EncodingType.valueOf(_getStringProp(msgCtxt, propName, "NONE").toUpperCase());
  }

  private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
    return _getEncodingTypeProperty(msgCtxt, "encode-result");
  }

  protected static byte[] decodeString(String s, EncodingType decodingKind) throws Exception {
    if (decodingKind == EncodingType.BASE16) {
      return Base16.decode(s);
    }
    if (decodingKind == EncodingType.BASE64) {
      return Base64.getDecoder().decode(s);
    }
    if (decodingKind == EncodingType.BASE64URL) {
      return Base64.getUrlDecoder().decode(s);
    }
    return s.getBytes(StandardCharsets.UTF_8);
  }

  protected PublicKey getPublicKey(MessageContext msgCtxt) throws Exception {
    return KeyUtil.decodePublicKey(_getRequiredString(msgCtxt, "public-key"));
  }

  protected PrivateKey getPrivateKey(MessageContext msgCtxt) throws Exception {
    return KeyUtil.decodePrivateKey(
        _getRequiredString(msgCtxt, "private-key"),
        _getOptionalString(msgCtxt, "private-key-password"));
  }

  private String _getRequiredString(MessageContext msgCtxt, String name) throws Exception {
    String value = _getStringProp(msgCtxt, name, null);
    if (value == null)
      throw new IllegalStateException(String.format("%s resolves to null or empty.", name));
    return value;
  }

  private String _getOptionalString(MessageContext msgCtxt, String name) throws Exception {
    return _getStringProp(msgCtxt, name, null);
  }

  protected boolean getDebug(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "debug", false);
  }

  protected boolean _getBooleanProperty(
      MessageContext msgCtxt, String propName, boolean defaultValue) throws Exception {
    String flag = this.properties.get(propName);
    if (flag != null) flag = flag.trim();
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    flag = resolveVariableReferences(flag, msgCtxt);
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    return flag.equalsIgnoreCase(TRUE);
  }

  protected String getMgf1Hash(MessageContext msgCtxt) throws Exception {
    return getMgf1Hash(msgCtxt, DEFAULT_MGF1_HASH);
  }

  protected String getMgf1Hash(MessageContext msgCtxt, String defaultHash) throws Exception {
    return _getStringProp(msgCtxt, "mgf1-hash", defaultHash);
  }

  protected static MGF1ParameterSpec getMGF1ParameterSpec(String mgf1Hash) {
    if ((mgf1Hash == null) || mgf1Hash.equals("")) {
      return MGF1ParameterSpec.SHA256;
    }
    return new MGF1ParameterSpec(mgf1Hash.toUpperCase());
  }

  protected static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }

  protected void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    String error = exc1.toString().replaceAll("\n", " ");
    msgCtxt.setVariable(varName("exception"), error);
    Matcher matcher = commonErrorPattern.matcher(error);
    if (matcher.matches()) {
      msgCtxt.setVariable(varName("error"), matcher.group(2));
    } else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }
}
