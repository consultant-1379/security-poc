/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.test.TestHelper;


public class CertificateUtilsTest {

    private static final String KEYALGY = "RSA";
    private static final String EXTCA_SIGALG = "SHA256withRSA";
    private static final int KEYSIZE = 1024;

    @Test
    public void testgeneratePKCS10Request() {
        try {
            KeyPair keyPair;

            keyPair = TestHelper.generateKeyPair(KEYALGY, KEYSIZE);

            final CredentialManagerSubject subject = new CredentialManagerSubject();
            subject.setCommonName("Pippo");
            final CredentialManagerEntity eentity = new CredentialManagerEntity();
            eentity.setSubject(subject);

            final CredentialManagerPKCS10CertRequest ret = new CredentialManagerPKCS10CertRequest(CertificateUtils.generatePKCS10Request(EXTCA_SIGALG, eentity, keyPair, null, BouncyCastleProvider.PROVIDER_NAME));
            assertTrue(ret != null);
        } catch (final NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | IOException e1) {
            assertTrue(false);
            e1.printStackTrace();
        }
    }

    @Test
    public void testgetCN() {
        final String dn = "CN=donald, O=duck, OU=paperopoli";
        final String cn = CertificateUtils.getCN(dn);
        Assert.assertEquals("donald", cn);
        final String dn2 = "CN=donald";
        final String cn2 = CertificateUtils.getCN(dn2);
        Assert.assertEquals("donald", cn2);
        final String dn3 = "CN,donald";
        final String cn3 = CertificateUtils.getCN(dn3);
        Assert.assertEquals(dn3,cn3);
        final String dn4 = "cn=donald, o=duck";
        final String cn4 = CertificateUtils.getCN(dn4);
        Assert.assertEquals("donald",cn4);
        final String dn5 = "o=duck, ou=paperopoli";
        final String cn5 = CertificateUtils.getCN(dn5);
        Assert.assertEquals(dn5,cn5);
        final String dn6 = "o=duck, cn=donald";
        final String cn6 = CertificateUtils.getCN(dn6);
        Assert.assertEquals("donald",cn6);
        final String dn7 = "o=duck";
        final String cn7 = CertificateUtils.getCN(dn7);
        Assert.assertEquals(dn7,cn7);
        final String dn8 = "cn=duck";
        final String cn8 = CertificateUtils.getCN(dn8);
        Assert.assertEquals("duck",cn8);
        final String dn9 = "duck";
        final String cn9 = CertificateUtils.getCN(dn9);
        Assert.assertEquals(dn9,cn9);
        
    }

}
