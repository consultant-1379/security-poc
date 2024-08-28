package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper.channelMode;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.JKSWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;

@RunWith(MockitoJUnitRunner.class)
public class CertificateUtilsTest {

    /*
     * Test to check certificate near expiration date
     */

    @Mock
    CredMServiceWrapper mockedWrapper;

    @Test
    public void CheckDateValidityTest() throws IssueCertificateException {
        final int PRE_EXPIRED_SKREW = 2; //(days) shift check expiration data forward
        when(this.mockedWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
        //Preparing a valid certificate which will expire in ten days from now
        X509Certificate cert = PrepareCertificate.prepareNearExpiringCertificate(PrepareCertificate.createKeyPair());
        List<String> warnTimer = new ArrayList<String>();
        warnTimer.add("10");//days (should print the warning log)
        try {
            CertificateUtils.checkDateValidity(cert, true, warnTimer, "pippo", PRE_EXPIRED_SKREW, mockedWrapper);
            assertTrue(true);
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            assertTrue(false);
        }

        warnTimer.clear();
        warnTimer.add("8");//days (should NOT print the warning log)
        try {
            CertificateUtils.checkDateValidity(cert, true, warnTimer, "pippo", PRE_EXPIRED_SKREW, mockedWrapper);
            assertTrue(true);
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            assertTrue(false);
        }
    }

    @Test
    public void buildIdentifierFromStringsTest() {

        /* it works */
        CredentialManagerCertificateIdentifier credManCertIdResult = CertificateUtils.buildIdentifierFromStrings("CN=anyIssuer", "CN=anySubject", "123456789");
        assertTrue("credManCertIdResult Null", credManCertIdResult != null);
        assertTrue("credManCertIdResult Null", credManCertIdResult.getSerialNumber().toString().equals("123456789"));

        /* case of null issuerDN */
        credManCertIdResult = CertificateUtils.buildIdentifierFromStrings(null, "CN=anySubject", "123456789");
        assertTrue("credManCertIdResult Not Null", credManCertIdResult == null);

        /* case of empty subjectDN */
        credManCertIdResult = CertificateUtils.buildIdentifierFromStrings("CN=anyIssuer", "", "123456789");
        assertTrue("credManCertIdResult Not Null", credManCertIdResult == null);

        /* case of null certificateSN */
        credManCertIdResult = CertificateUtils.buildIdentifierFromStrings("CN=anyIssuer", "CN=anySubject", null);
        assertTrue("credManCertIdResult Not Null", credManCertIdResult == null);

        /* case of issuer not valid */
        credManCertIdResult = CertificateUtils.buildIdentifierFromStrings("anyIssuer", "CN=anySubject", "123456789");
        assertTrue("credManCertIdResult Not Null", credManCertIdResult == null);

        /* case of not valid certificateSN */
        credManCertIdResult = CertificateUtils.buildIdentifierFromStrings("CN=anyIssuer", "CN=anySubject", "ABCD");
        assertTrue("credManCertIdResult Not Null", credManCertIdResult == null);
        
        /* case of empty issuerDN */
        credManCertIdResult = CertificateUtils.buildIdentifierFromStrings("", "CN=anySubject", null);
        assertTrue("credManCertIdResult Not Null", credManCertIdResult == null);
        
        /* case of null subjectDN */
        credManCertIdResult = CertificateUtils.buildIdentifierFromStrings("CN=anyIssuer", null, null);
        assertTrue("credManCertIdResult Not Null", credManCertIdResult == null);
        
        /* case of empty certificateSN*/
        credManCertIdResult = CertificateUtils.buildIdentifierFromStrings("CN=anyIssuer", "CN=anySubject", "");
        assertTrue("credManCertIdResult Not Null", credManCertIdResult == null);
    }
    
    @Test
    public void buildIdentifierTestFail() {
        CertificateUtils cu = new CertificateUtils(); //just for coverage
        assertTrue(cu != null);
        assertTrue(CertificateUtils.buildIdentifier(null) == null);
    }
    
    @Test
    public void generatePKCS10Requesttest() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        try {
            CertificateUtils.generatePKCS10Request("SHA256WITHRSA", new X500Name("Cn=cn"), PrepareCertificate.createKeyPair(), null);
            assertTrue(true);
        } catch (Exception e) {
            assertTrue(false);
        }
    }
    
    @Test
    public void retrieveCertificateIdtest() throws IOException, StorageException {
        
        KeystoreInfo keyStoreCert = new KeystoreInfo(null, "fakePK", null, "", CertificateFormat.JKS, "pwd", "wrongalias"); //private key not needed
        assertTrue(CertificateUtils.retrieveCertificateId(keyStoreCert) == null);
        keyStoreCert.setKeyAndCertLocation("");
        keyStoreCert.setCertificateLocation("");
        assertTrue(CertificateUtils.retrieveCertificateId(keyStoreCert) == null);
        keyStoreCert.setCertificateLocation("/tmp/certOnly.jks");
        assertTrue(CertificateUtils.retrieveCertificateId(keyStoreCert) == null);
        File keyStoreFile = new File(keyStoreCert.getCertificateLocation());
        keyStoreFile.createNewFile();
        assertTrue(CertificateUtils.retrieveCertificateId(keyStoreCert) == null);
        assertTrue(keyStoreFile.delete());
        CredentialWriter jksWriter = new JKSWriter(keyStoreCert.getKeyStoreFolder(),keyStoreCert.getCertificateLocation(),keyStoreCert.getKeyStorePwd(),keyStoreCert.getCertFormat().name());
        X509Certificate cert1 = PrepareCertificate.prepareCertificate(PrepareCertificate.createKeyPair());
        jksWriter.addTrustedEntry(cert1, "truealias");
        assertTrue(CertificateUtils.retrieveCertificateId(keyStoreCert) == null);
        assertTrue(keyStoreFile.delete());
    }
    
    @Test
    public void CertificateRevocationListUtilsFailTest() {
        CertificateRevocationListUtils util = new CertificateRevocationListUtils(); //just to cover
        assertTrue(util != null);
        assertTrue(CertificateRevocationListUtils.buildIdentifier(null) == null);
    }
}
