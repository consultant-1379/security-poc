package com.ericsson.oss.itpf.security.credmsapi;

import static org.junit.Assert.assertTrue;

import org.junit.Assert;
import org.junit.Test;

public class CredentialManagerProfileTypeTest {

    @Test
    public void test1() {
        CredentialManagerProfileType prof1 = CredentialManagerProfileType.ENTITY_PROFILE;
        Assert.assertEquals(prof1.getValue(),"entityprofile");
        Assert.assertNotEquals(prof1.toString(), prof1);
        Assert.assertEquals(prof1,CredentialManagerProfileType.fromValue("entityprofile"));
        Assert.assertNotEquals(prof1,CredentialManagerProfileType.fromValue("certificateprofile"));
        CredentialManagerProfileType prof2 = null;
        try{
            prof2 = CredentialManagerProfileType.fromValue("fakeProfileType");
            assertTrue(false);
        } catch (IllegalArgumentException e) {
            assertTrue(prof2 == null);
        }
    }
    
}
