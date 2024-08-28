package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerBasicConstraints;

public class CredentialManagerExtensionBasicConstraintsTest {

    @Test
    public void CMExtensionBasicConstraintsTest() {
        CredentialManagerExtensionBasicConstraints cmMnBC = new CredentialManagerExtensionBasicConstraints(null);
        assertTrue(cmMnBC != null && cmMnBC.getBasicConstraintsName().equals("basicConstraintsName") && cmMnBC.getAttributes() == null);
        CredentialManagerBasicConstraints cmBC = new CredentialManagerBasicConstraints();
        cmBC.setCA(true);
        cmBC.setEnabled(true);
        cmBC.setPathLenConstraint(3);
        cmMnBC = new CredentialManagerExtensionBasicConstraints(cmBC);
        assertTrue(cmMnBC.getAttributes().get("basicConstraintsName") != null);
    }
    
}