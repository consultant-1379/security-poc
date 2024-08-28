/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.naming.NamingException;

import org.apache.commons.cli.ParseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerKeyStoreImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerTrustStoreImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerKeyStore;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerTrustStore;


@RunWith(JUnit4.class)
public class CredMaKeyStoreTest {

    @Test
    public void testBase64() throws NamingException, ParseException, IOException {
        
        final KeyStoreType kst = new KeyStoreType();
        final TrustStoreType tst = new TrustStoreType();
        
        final Base64KStoreType keyb64 = new Base64KStoreType();
        keyb64.setStorealias("pippo");
        keyb64.setStorelocation("ks.pem");
        keyb64.setCertificatefilelocation("cert.cer");
        keyb64.setKeyfilelocation("key.key");
        keyb64.setStorepassword("password");
        kst.setBase64Keystore(keyb64);
        final CredentialManagerKeyStore keyStore = new CredentialManagerKeyStoreImpl(kst);
        assertTrue("testBase64", "pippo".equals(keyStore.getAlias()));
        assertTrue("testBase64", "cert.cer".equals(keyStore.getCertificateLocation()));
        assertTrue("testBase64", "key.key".equals(keyStore.getPrivateKeyLocation()));
        assertTrue("testBase64", "ks.pem".equals(keyStore.getKeyStorelocation()));
        assertTrue("testBase64", "password".equals(keyStore.getPassword()));
        
        final Base64TStoreType trustb64 = new Base64TStoreType();
        trustb64.setStorealias("pippo");
        trustb64.setStorelocation("ks.pem");
        trustb64.setStorefolder("cert");
        trustb64.setStorepassword("password");
        tst.setBase64Truststore(trustb64);
        final CredentialManagerTrustStore trustStore = new CredentialManagerTrustStoreImpl(tst);
        assertTrue("testBase64", "pippo".equals(trustStore.getAlias()));
        assertTrue("testBase64", "ks.pem".equals(trustStore.getLocation()));
        assertTrue("testBase64", "cert".equals(trustStore.getFolder()));
        assertTrue("testBase64", "password".equals(trustStore.getPassword()));               
    }
    
    @Test
    public void testJKS() throws NamingException, ParseException, IOException {
    	
        final KeyStoreType kst = new KeyStoreType();
        final TrustStoreType tst = new TrustStoreType();
        
        final KStoreType kjks = new KStoreType();
        kjks.setStorealias("pippo");
        kjks.setStorelocation("ks.pem");
        kjks.setStorepassword("password");
        kst.setJkskeystore(kjks);
        final CredentialManagerKeyStore keyStore = new CredentialManagerKeyStoreImpl(kst);
        assertTrue("testJKS", "pippo".equals(keyStore.getAlias()));
        assertTrue("testJKS", "ks.pem".equals(keyStore.getKeyStorelocation()));
        assertTrue("testJKS", "password".equals(keyStore.getPassword()));
        
        final TStoreType tjks = new TStoreType();
        tjks.setStorealias("pippo");
        tjks.setStorefolder("cert");
        tjks.setStorelocation("ks.pem");
        tjks.setStorepassword("password");
        tst.setJkstruststore(tjks);
        final CredentialManagerTrustStore trustStore = new CredentialManagerTrustStoreImpl(tst);
        assertTrue("testJKS", "pippo".equals(trustStore.getAlias()));
        assertTrue("testJKS", "ks.pem".equals(trustStore.getLocation()));
        assertTrue("testJKS", "cert".equals(trustStore.getFolder()));
        assertTrue("testJKS", "password".equals(trustStore.getPassword()));
    }
    
    @Test
    public void testJCEKS() throws NamingException, ParseException, IOException {
        
        final KeyStoreType kst = new KeyStoreType();
        final TrustStoreType tst = new TrustStoreType();
        
        final KStoreType kjceks = new KStoreType();
        kjceks.setStorealias("pippo");
        kjceks.setStorelocation("ks.pem");
        kjceks.setStorepassword("password");
        kst.setJcekskeystore(kjceks);
        final CredentialManagerKeyStore keyStore = new CredentialManagerKeyStoreImpl(kst);
        assertTrue("testJCEKS", "pippo".equals(keyStore.getAlias()));
        assertTrue("testJCEKS", "ks.pem".equals(keyStore.getKeyStorelocation()));
        assertTrue("testJCEKS", "password".equals(keyStore.getPassword()));
        
        final TStoreType tjceks = new TStoreType();
        tjceks.setStorealias("pippo");
        tjceks.setStorefolder("cert");
        tjceks.setStorelocation("ks.pem");
        tjceks.setStorepassword("password");
        tst.setJcekstruststore(tjceks);
        final CredentialManagerTrustStore trustStore = new CredentialManagerTrustStoreImpl(tst);
        assertTrue("testJCEKS", "pippo".equals(trustStore.getAlias()));
        assertTrue("testJCEKS", "ks.pem".equals(trustStore.getLocation()));
        assertTrue("testJCEKS", "cert".equals(trustStore.getFolder()));
        assertTrue("testJCEKS", "password".equals(trustStore.getPassword()));   
    }
    
    @Test
    public void testPKCS12() throws NamingException, ParseException, IOException {
        
        final KeyStoreType kst = new KeyStoreType();
        final TrustStoreType tst = new TrustStoreType();
        
        final KStoreType kpkcs = new KStoreType();
        kpkcs.setStorealias("pippo");
        kpkcs.setStorelocation("ks.pem");
        kpkcs.setStorepassword("password");
        kst.setPkcs12Keystore(kpkcs);
        final CredentialManagerKeyStore keyStore = new CredentialManagerKeyStoreImpl(kst);
        assertTrue("testPKCS12", "pippo".equals(keyStore.getAlias()));
        assertTrue("testPKCS12", "ks.pem".equals(keyStore.getKeyStorelocation()));
        assertTrue("testPKCS12", "password".equals(keyStore.getPassword()));
        
        final TStoreType tpkcs = new TStoreType();
        tpkcs.setStorealias("pippo");
        tpkcs.setStorefolder("cert");
        tpkcs.setStorelocation("ks.pem");
        tpkcs.setStorepassword("password");
        tst.setPkcs12Truststore(tpkcs);
        final CredentialManagerTrustStore trustStore = new CredentialManagerTrustStoreImpl(tst);
        assertTrue("testPKCS12", "pippo".equals(trustStore.getAlias()));
        assertTrue("testPKCS12", "ks.pem".equals(trustStore.getLocation()));
        assertTrue("testPKCS12", "cert".equals(trustStore.getFolder()));
        assertTrue("testPKCS12", "password".equals(trustStore.getPassword()));        
    }
    
    
}
