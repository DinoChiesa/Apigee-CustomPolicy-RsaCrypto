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

public abstract class TestRsaBase {

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  protected MessageContext msgCtxt;
  protected ExecutionContext exeCtxt;

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
            Object value = getVariables().get(name);
            //System.out.printf("%s = %s\n", name, (value==null) ? "-nul-" : value.toString());
            return value;
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            //System.out.printf("%s <= %s\n", name, (value==null) ? "-nul-" : value);
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

  final protected static String privateKey1 =
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

  final protected static String publicKey1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA15PZNNSa4RkH9eAeJ8ph\n"
          + "57WhvUmANpBEDqP0SuHzNl3HmxbEiUPBoBNQAtRpVlOWM0t+FltMORjGXtntjSBs\n"
          + "/8do3kaPbKN4Ua0O/wRpe15wHnRBNT+V5qonUDy0R+gfBqBpMNVIn2b1x5EWih10\n"
          + "sMCU+rjnUvBYtCGHmbQlUcZOZbXLSWfV3ukoRaGG2KV9V2zNXWjTZiKSFRFJZSeW\n"
          + "4sT+s9twcmx+QF60xkpqe4/DvrqanKb3bKGQoViC0wl67vzv+QfaLtku/WAsBeLm\n"
          + "I3DFmXb0ny3uCUCfCRtHnpAU0gfjWBiwkZ/R2OhZOW877GGcNMKVTnFT6911gGMi\n"
          + "SwIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";
}
