package com.ericsson.oss.services.cm.admin.cli.utils;

import com.ericsson.oss.services.cm.admin.utility.PasswordHelper;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.function.Function;

@RunWith(MockitoJUnitRunner.class)
public class ParameterValueSnmpConverterTest {

    @Mock
    private FilterContext filterContext;

    @Mock
    private PasswordHelper passwordHelper;

    private ParameterValueSnmpConverter parameterValueSnmpConverter = new ParameterValueSnmpConverter();

    @Test
    public void convertSnmpDataCorrectlyTest() {
        Function<String, String> passwordDecoder = password -> passwordHelper.decryptDecode(password);
        Mockito.when(passwordHelper.decryptDecode(Mockito.anyString())).thenReturn("DecryptedPassword");
        Mockito.when(filterContext.getPasswordDecoder()).thenReturn(passwordDecoder);
        Mockito.when(filterContext.getParameterValue()).thenReturn("[\"securityLevel:NO_AUTH_NO_PRIV\",\"authPassword:EncryptedPassword\",\"authProtocol:NONE\",\"privPassword:EncryptedPassword\",\"privProtocol:NONE\",\"user:defaultsnmpuser\"]");
        String actual = parameterValueSnmpConverter.convert(filterContext);
        Assert.assertEquals("{securityLevel:NO_AUTH_NO_PRIV,authProtocol:NONE,authPassword:DecryptedPassword,privProtocol:NONE,privPassword:DecryptedPassword,user:defaultsnmpuser}", actual);
    }

    @Test
    public void convertSnmpDataWrongTest() {
        Function<String, String> passwordDecoder = password -> passwordHelper.decryptDecode(password);
        Mockito.when(passwordHelper.decryptDecode(Mockito.anyString())).thenReturn("DecryptedPassword");
        Mockito.when(filterContext.getPasswordDecoder()).thenReturn(passwordDecoder);
        Mockito.when(filterContext.getParameterValue()).thenReturn("[\"Name:Test\",\"Address:Ireland\"]");
        String actual = parameterValueSnmpConverter.convert(filterContext);
        Assert.assertNull(actual);
    }

}