package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.Key;
import java.security.cert.CRL;
import java.security.cert.Certificate;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStorageException;

@RunWith(JUnit4.class)
public class Base64StoreTest {

    final String ksFilename = System.getProperty("user.dir") + "/src/test/resources/base64keystore.pem";
    //  TODO
    // using a password with "AES-256-CFB" encryption algorithm Maven fails to perform the test
    // it seems not find the correct library or the JVM doent support an high cyper mode
    // org.bouncycastle.openssl.encryptionexception: exception using cipher - please check password and data.
    // Caused by: java.security.InvalidKeyException: Illegal key size
    final String base64Password = "pippo";

    @Test
    public void testBase64SingleKeyStore() {
        final Base64Reader br = new Base64Reader("", this.ksFilename, "", "", this.base64Password);
        Key myKey = null;
        try {
            myKey = br.getPrivateKey("alias");
        } catch (final CredentialManagerStorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("Key read", myKey != null);

        Certificate myCert = null;
        try {
            myCert = br.getCertificate("alias");
            System.out.println("cert : " + myCert.getType());
        } catch (final CredentialManagerStorageException e) {
            e.printStackTrace();
        }
        assertTrue("Certificate read", myCert != null);
        
        Certificate[] myCertArray = null;
        
        try {
            myCertArray = br.getCertificateChain("alias");
            System.out.println("cert : " + myCertArray[0].getType()); //just one entry
        } catch (final CredentialManagerStorageException e) {
            e.printStackTrace();
        }
        assertTrue("Certificate Chain read", myCert != null);
        assertTrue("Certificate Chain lenght", myCertArray.length == 1);
    }

    @Test
    public void testTEMPcrl() {
        Base64Reader b64r = null;
        try {//not existent file
            b64r = new Base64Reader("", "src/test/resources/crl.pem", "", "", "");
            final CRL crl = b64r.getCRL("alias");
            assertTrue(false);
        } catch (final CredentialManagerStorageException e) {
            assertTrue(true);
        }
        try {
            b64r = new Base64Reader("",System.getProperty("user.dir") + "/src/test/resources/VC_Root_CA_A1.crl", "", "", "");
            final CRL crl2 = b64r.getCRL("alias");
            assertTrue("CRL empty", crl2 == null);
        } catch (final CredentialManagerStorageException e) {
            assertTrue(false);
        }
        try {
            b64r = new Base64Reader("",System.getProperty("user.dir") + "/src/test/resources/rootCrl.pem", "", "", "");
            final CRL crl3 = b64r.getCRL("alias");
            assertTrue("CRL reading", crl3 != null && crl3.getType().equals("X.509"));
        } catch (final CredentialManagerStorageException e) {
            assertTrue(false);
        }
    }

    @Test
    public void b64readTest() {        
        Base64Reader b64r = new Base64Reader("", "", this.ksFilename,System.getProperty("user.dir") + "/src/test/resources/privateCredmTest.pem", this.base64Password);
        Key key = null;
        try {
            key = b64r.getPrivateKey(null);
            assertTrue(key != null && key.getAlgorithm().equals("RSA"));
        } catch (CredentialManagerStorageException e) {
            assertTrue(false);
        }
        Certificate cert = null;
        try {
            cert = b64r.getCertificate(null);
            assertTrue(cert != null);
        } catch (CredentialManagerStorageException e) {
            assertTrue(false);
        }
        
        b64r = new Base64Reader(System.getProperty("user.dir") + "/src/test/resources/folder64Test/","","","",this.base64Password);
        try {
            Certificate[] certs = b64r.getCertificateChain("alias");
            assertTrue(certs[0] == cert);
        } catch (CredentialManagerStorageException e) {
            assertTrue(false);
        }
    }
    
}
