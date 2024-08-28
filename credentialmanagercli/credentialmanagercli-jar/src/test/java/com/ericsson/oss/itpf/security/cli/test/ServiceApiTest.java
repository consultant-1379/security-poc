package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerActionCauseEnum;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerActionEnum;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCommandType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerConnectorManagedType;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ServiceApiTest {

    @Test
    public void CMActionCauseEnumTest() {
        CredentialManagerActionCauseEnum cmACE = CredentialManagerActionCauseEnum.TRUST_UPDATE;
        assertTrue(!cmACE.equals(null));
        assertTrue(!cmACE.equals("wrongValue"));
        assertTrue(!cmACE.equals("certificateUpdate"));
        assertTrue(cmACE.equals("trustUpdate"));  
    }
    
    @Test
    public void CredentialManagerActionEnumTest() {
        CredentialManagerActionEnum cmAE = CredentialManagerActionEnum.HTTPS_CONNECTOR_RESTART;
        assertTrue(!cmAE.equals(null));
        assertTrue(!cmAE.equals("wrongValue"));
        assertTrue(!cmAE.equals("VMRestart"));
        assertTrue(cmAE.equals("HTTPSConnectorRestart")); 
    }
    
    @Test
    public void CredentialManagerCommandTypeTest() {
        
        CredentialManagerCommandType cmCT = new CredentialManagerCommandType();
        assertTrue(cmCT.getParameterName() != null && cmCT.getParameterValue() != null && cmCT.getPathname() != null);
        List<String> parValueList = new ArrayList<String>();
        List<String> parList = new ArrayList<String>();
        List<String> scriptList = new ArrayList<String>();
        parValueList.add("value1");
        parValueList.add("value2");
        parList.add("param1");
        parList.add("param2");
        scriptList.add("script1");
        scriptList.add("script2");
        cmCT.setParameterName(parList);
        cmCT.setParameterValue(parValueList);
        cmCT.setPathname(scriptList);
        cmCT.addParameterValue("value3");
        cmCT.addParameterName("param3");
        assertTrue(cmCT.getParameterValue().get(1).equals("value2"));
    }
    
    @Test
    public void CredentialManagerConnectorManagedTypeTest() {
        
        CredentialManagerConnectorManagedType cmCM = CredentialManagerConnectorManagedType.UNDEFINED;
        assertTrue(cmCM.value().equals("undefined"));
        CredentialManagerConnectorManagedType cmCM1 = null;
        try {
            cmCM1 = CredentialManagerConnectorManagedType.fromValue("fakeValue");
            assertTrue(false);
        } catch(IllegalArgumentException e) {
            assertTrue(cmCM1 == null);
        }
        CredentialManagerConnectorManagedType cmCM2 = CredentialManagerConnectorManagedType.fromValue("httpsConnector");
        assertTrue(cmCM2.value().equals("httpsConnector"));
        assertTrue(CredentialManagerConnectorManagedType.valueOf("HTTPS_CONNECTOR").equals(CredentialManagerConnectorManagedType.HTTPS_CONNECTOR));
        assertTrue(CredentialManagerConnectorManagedType.values().length == 2);
    }
    
}
