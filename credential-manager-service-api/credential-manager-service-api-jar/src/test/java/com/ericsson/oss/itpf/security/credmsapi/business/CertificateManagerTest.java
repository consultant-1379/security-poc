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
package com.ericsson.oss.itpf.security.credmsapi.business;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.iptf.security.credmsapi.test.utils.CertificateWriter;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper.channelMode;
import com.ericsson.oss.itpf.security.credmsapi.CredentialManagerServiceRestClient;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateValidationException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtensionImpl;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.CertHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CertHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerSubjectAlternateName;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerSubjectAlternateNameImpl;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateExsitsException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidCSRException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagerTest {

    String xmlSubject = "O=OpenDJ, CN=Administrator";

    @InjectMocks
    CredMServiceWrapper mockWrapper;
    @Mock
    static CredentialManagerServiceRestClient mockRestCLient;
    @Mock
    static CredMService mockRmiClient;

    @Mock
    CredMServiceWrapper mockedWrapper;

    /**
     * Test method for checkCertificateValidation(KeystoreInfo keyStoreCert) - invalid Certificate format
     */
    @Test
    public void testCheckCertificateValidityJksWrongFormat() {

        /*
         * Certificate generation and storage (PKCS12)
         */

        final CertificateManager certificateManager = new CertificateManager(null);

        final List<KeystoreInfo> testKeyStoreInfo = CertificateWriter.writeKeyAndCertificatePKCS12(certificateManager,
                CertificateWriter.CertMode.valid);

        final CredentialManagerEntity entity = new CredentialManagerEntity();

        /**
         * Set Wrong format (JKS)
         */
        testKeyStoreInfo.get(0).setCertFormat(CertificateFormat.JKS);

        /**
         * Test execution
         */
        try {
            assertFalse(certificateManager.checkCertificateValidity(testKeyStoreInfo.get(0), this.xmlSubject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationJksWrongFormat failed!", false);
        } finally {
            File p12file = new File("/tmp/keyAndCertTest.p12");
            if(p12file.exists()) {
                assertTrue(p12file.delete());
            }
        }

    }

    /**
     * Test method for checkCertificateValidation(KeystoreInfo keyStoreCert) - Valid Certificate
     */
    @Test
    public void testCheckCertificateValidityJksOK() {

        /*
         * Certificate generation and storage
         */
        final CertificateManager certificateManagerMock = new CertificateManager(mockedWrapper);

        final List<KeystoreInfo> testKeyStoreInfo = CertificateWriter.writeKeyAndCertificateJKS(certificateManagerMock,
                CertificateWriter.CertMode.valid);

        /**
         * Setting of expected parameters
         */
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        final CredentialManagerSubject issuerDN = new CredentialManagerSubject();
        entity.setName("myEntity");
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        entity.setIssuerDN(issuerDN.updateFromSubjectDN("CN=rootCA, OU=ericsson, O=ericsson, L=Unknown, ST=Unknown, C=Unknown"));
        final String subject = "CN=CN";

        /**
         * Test execution
         */
        try {
            when(this.mockedWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
            assertTrue(certificateManagerMock.checkCertificateValidity(testKeyStoreInfo.get(0), subject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationJksOK failed!", false);
        } finally {
            File kfile = new File("/tmp/keyAndCertTest.jks");
            if(kfile.exists()) {
                assertTrue(kfile.delete());
            }
        }

    }

    /**
     * Test method for checkCertificateValidation(KeystoreInfo keyStoreCert) - Certificate not present
     */
    @Test
    public void testCheckCertificateValidityJksNOTPRESENT() {

        /**
         * No certificate generation, non-existing file used (certStoreName)
         */
        final String certStoreName = "src/test/resources/admin-keystore1";
        final String certPassword = "password";
        final String certAlias = "admin-cert";
        final KeystoreInfo testKeyStoreInfo = new KeystoreInfo(null, null, null, null, CertificateFormat.JKS, null, null);

        testKeyStoreInfo.setKeyAndCertLocation(certStoreName);
        testKeyStoreInfo.setKeyStorePwd(certPassword);
        testKeyStoreInfo.setAlias(certAlias);

        final CertificateManager certificateManager = new CertificateManager(null);
        final CredentialManagerEntity entity = new CredentialManagerEntity();

        try {
            assertTrue(!certificateManager.checkCertificateValidity(testKeyStoreInfo, this.xmlSubject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationJksNOTPRESENT failed!", false);
        }

    }

    /**
     * Test method for checkCertificateValidation(KeystoreInfo keyStoreCert) - Expired JKS Certificate
     */
    @Test
    public void testCheckCertificateValidityJksExpired() {

        /*
         * Certificate generation and storage
         */
        final CertificateManager certificateManagerMock = new CertificateManager(mockedWrapper);

        final List<KeystoreInfo> testKeyStoreInfo = CertificateWriter.writeKeyAndCertificateJKS(certificateManagerMock,
                CertificateWriter.CertMode.expired);

        /**
         * Setting of expected parameters
         */
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setName("myEntity");
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        final String subject = "CN=CN";

        /**
         * Test execution
         */
        try {
            when(this.mockedWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
            assertTrue(!certificateManagerMock.checkCertificateValidity(testKeyStoreInfo.get(0), subject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationJksOK failed!", false);
        } finally {
            File kfile = new File("/tmp/keyAndCertTest.jks");
            if(kfile.exists()) {
                assertTrue(kfile.delete());
            }
        }

    }

    @Test
    public void testCheckCertificateValidityJksNotYetValid() {

        /*
         * Certificate generation and storage
         */
        final CertificateManager certificateManagerMock = new CertificateManager(mockedWrapper);

        final List<KeystoreInfo> testKeyStoreInfo = CertificateWriter.writeKeyAndCertificateJKS(certificateManagerMock,
                CertificateWriter.CertMode.notYetValid);

        /**
         * Setting of expected parameters
         */
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setName("myEntity");
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        final String subject = "CN=CN";

        /**
         * Test execution
         */
        try {
            when(this.mockedWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
            assertTrue(!certificateManagerMock.checkCertificateValidity(testKeyStoreInfo.get(0), subject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationJksOK failed!", false);
        } finally {
            File kfile = new File("/tmp/keyAndCertTest.jks");
            if(kfile.exists()) {
                assertTrue(kfile.delete());
            }
        }

    }

    /**
     * Test method for checkCertificateValidation(KeystoreInfo keyStoreCert) - Valid Certificate
     */
    @Test
    public void testCheckCertificateValidityJksNOTSET() {

        final KeystoreInfo testKeyStoreInfo = new KeystoreInfo(null, null, null, null, CertificateFormat.JKS, null, null);

        final CertificateManager certificateManager = new CertificateManager(null);
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();
        profileInfo.setIssuerName("CN=ENM PKI Root CA");

        /**
         * Test execution: No certificate location set
         */
        try {
            certificateManager.checkCertificateValidity(testKeyStoreInfo, "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown",
                    entity, true, getMockPIBParameters());
            assertTrue("Exception not occurred", false);
        } catch (final CertificateValidationException e) {

            if (e.getMessage().contains("file location not set!")) {
                assertTrue(true);
            } else {
                assertTrue("Wrong exception occurred!", false);
            }
        }

        /**
         * Test execution: all certificate locations set
         */
        testKeyStoreInfo.setKeyAndCertLocation("KeyAndCertLocation");
        testKeyStoreInfo.setPrivateKeyLocation("PrivateKeyLocation");
        testKeyStoreInfo.setCertificateLocation("CertificateLocation");

        try {
            certificateManager.checkCertificateValidity(testKeyStoreInfo, "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown",
                    entity, true, getMockPIBParameters());
            assertTrue("Exception not occurred", false);
        } catch (final CertificateValidationException e) {

            if (e.getMessage().contains("multiple file location setting found!")) {
                assertTrue(true);
            } else {
                assertTrue("Wrong exception occurred!", false);
            }
        }

    }

    @Test
    public void testCheckCertificateValidityPkcs12OK() {

        /*
         * Certificate generation and storage (PKCS12)
         */
        final CertificateManager certificateManagerMock = new CertificateManager(mockedWrapper);

        final List<KeystoreInfo> testKeyStoreInfo = CertificateWriter.writeKeyAndCertificatePKCS12(certificateManagerMock,
                CertificateWriter.CertMode.valid);

        /**
         * Setting of expected parameters
         */
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        final CredentialManagerSubject issuerDN = new CredentialManagerSubject();
        entity.setName("myEntity");
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        entity.setIssuerDN(issuerDN.updateFromSubjectDN("CN=rootCA, OU=ericsson, O=ericsson, L=Unknown, ST=Unknown, C=Unknown"));
        final String subject = "CN=CN";

        /**
         * Test execution
         */
        boolean result = false;
        try {
            when(this.mockedWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
            result = certificateManagerMock.checkCertificateValidity(testKeyStoreInfo.get(0), subject, entity, true, getMockPIBParameters());
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationPkcs12OK failed!", false);
        }
        assertTrue("checkCertificateValidity not OK", result);

        /**
         * Test Execution (wrong alias)
         */
        testKeyStoreInfo.get(0).setAlias("pippoXXX");
        try {
            when(this.mockedWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
            result = certificateManagerMock.checkCertificateValidity(testKeyStoreInfo.get(0), subject, entity, true, getMockPIBParameters());
        } catch (final CertificateValidationException e) {
            assertTrue("Exception occurred!", false);
        } finally {
            File p12file = new File("/tmp/keyAndCertTest.p12");
            if(p12file.exists()) {
               assertTrue(p12file.delete());
            }
        }
        assertTrue("checkCertificateValidity FAILED OK", !result);
    }

    @Test
    public void testCheckCertificateValidityPkcs12Expired() {

        /*
         * Certificate generation and storage
         */
        final CertificateManager certificateManagerMock = new CertificateManager(mockedWrapper);

        final List<KeystoreInfo> testKeyStoreInfo = CertificateWriter.writeKeyAndCertificatePKCS12(certificateManagerMock,
                CertificateWriter.CertMode.expired);

        /**
         * Setting of expected parameters
         */
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setName("myEntity");
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        final String subject = "CN=CN";

        /**
         * Test execution
         */
        try {
            when(this.mockedWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
            assertTrue(!certificateManagerMock.checkCertificateValidity(testKeyStoreInfo.get(0), subject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidityPkcs12Expired failed!", false);
        } finally {
            File p12file = new File("/tmp/keyAndCertTest.p12");
            if(p12file.exists()) {
                assertTrue(p12file.delete());
            }
        }

    }

    @Test
    public void testCheckCertificateValidityBase64OK() {

        final String certStoreNameKC = "certStoreNameKC.pem";
        final String certStoreNameOnlyC = "certStoreNameOnlyC.cer";
        final String certStoreNameOnlyK = "certStoreNameOnlyK.key";

        final KeystoreInfo keyStoreInfo = new KeystoreInfo(null, null, null, null, CertificateFormat.BASE_64, "", "");

        final CertificateManager certificateManager = new CertificateManager(null);
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        final CredentialManagerSubject issuerDN = new CredentialManagerSubject();
        issuerDN.updateFromSubjectDN("C=Unknown,ST=Unknown,L=Unknown,O=ericsson,OU=ericsson,CN=rootCA");

        /**
         * Certificate Only in input file
         */
        keyStoreInfo.setCertificateLocation(certStoreNameOnlyC);

        try {
            assertFalse(certificateManager.checkCertificateValidity(keyStoreInfo, this.xmlSubject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationBase64OK failed!", true);
        }

        /**
         * fix the key file location (Certificate file does not exist)
         */
        keyStoreInfo.setPrivateKeyLocation(certStoreNameOnlyK);

        try {
            assertFalse(certificateManager.checkCertificateValidity(keyStoreInfo, this.xmlSubject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationBase64OK failed!", false);
        }

        /**
         * Certificate file is created (Key file does not exist)
         */
        final File certFile = new File(certStoreNameOnlyC);
        try {
            certFile.createNewFile();
        } catch (final IOException e) {
            assertTrue("Unable to create new file", false);
        }

        try {
            assertFalse(certificateManager.checkCertificateValidity(keyStoreInfo, this.xmlSubject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationBase64OK failed!", false);
        } finally {
            if(certFile.exists()) {
                assertTrue(certFile.delete());
            }
        }

        /**
         * Certificate location, Key location and KeyAndCertificate location set
         */
        keyStoreInfo.setKeyAndCertLocation(certStoreNameKC);

        try {
            assertFalse(certificateManager.checkCertificateValidity(keyStoreInfo, this.xmlSubject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationBase64OK failed!", true);
        }

        /**
         * Key location and Certificate location cleared
         */
        keyStoreInfo.setCertificateLocation(null);
        keyStoreInfo.setPrivateKeyLocation(null);

        /**
         * Only KeyAndCertificate location set, check for null alias
         */
        keyStoreInfo.setAlias(null);

        try {
            assertFalse(certificateManager.checkCertificateValidity(keyStoreInfo, this.xmlSubject, entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationBase64OK failed!", true);
        }

        /**
         * Mockito Test (certificate locally generated)
         */
        /*
         * Certificate generation and storage (BASE64)
         */
        final CertificateManager certificateManagerMock = new CertificateManager(mockedWrapper);

        final List<KeystoreInfo> testKeyStoreInfo = CertificateWriter.writeKeyAndCertificateBASE64(certificateManagerMock,
                CertificateWriter.CertMode.valid);

        /**
         * Setting of expected parameters
         */
        //final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setName("myEntity");
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        entity.setIssuerDN(issuerDN);
        final String subject = "CN=CN";

        /**
         * Test execution (validity)
         */
        boolean result = false;
        try {
            when(this.mockedWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
            result = certificateManagerMock.checkCertificateValidity(testKeyStoreInfo.get(0), subject, entity, true, getMockPIBParameters());
        } catch (final CertificateValidationException e) {
            assertTrue("testCheckCertificateValidationBase64OK failed!", false);
        } finally {
            File b64File = new File("/tmp/keyAndCertTest.pem");
            if(b64File.exists()) {
                assertTrue(b64File.delete());
            }
        }
        assertTrue("checkCertificateValidity not OK", result);
    }

    @Test
    public void testCheckCertificateValidityFails() {
        final CertificateManager certificateManager = new CertificateManager(null);
        final String subj = "O=oooo, CN=ccnnnnn";
        KeystoreInfo ksInfo = new KeystoreInfo(null, null, "/tmp", null, null, null, null);
        final CredentialManagerEntity cmEnt = new CredentialManagerEntity();
        final CredentialManagerPIBParameters cmPib = new CredentialManagerPIBParameters();
        try {
            certificateManager.checkCertificateValidity(ksInfo, subj, cmEnt, false, cmPib);
            assertTrue(false);
        } catch (final CertificateValidationException e) {
            assertTrue(true);
        }
        ksInfo.setPrivateKeyLocation("");
        try {
            certificateManager.checkCertificateValidity(ksInfo, subj, cmEnt, false, cmPib);
            assertTrue(false);
        } catch (final CertificateValidationException e) {
            assertTrue(true);
        }
        ksInfo.setPrivateKeyLocation("/tmp");
        try {
            certificateManager.checkCertificateValidity(ksInfo, subj, cmEnt, false, cmPib);
            assertTrue(false);
        } catch (final CertificateValidationException e) {
            assertTrue(true);
        }
        ksInfo.setKeyAndCertLocation("");
        try {
            certificateManager.checkCertificateValidity(ksInfo, subj, cmEnt, false, cmPib);
            assertTrue(false);
        } catch (final CertificateValidationException e) {
            assertTrue(true);
        }
        ksInfo = new KeystoreInfo("", null, null, null, null, null, null);
        try {
            certificateManager.checkCertificateValidity(ksInfo, subj, cmEnt, false, cmPib);
            assertTrue(false);
        } catch (final CertificateValidationException e) {
            assertTrue(true);
        }
        ksInfo = new KeystoreInfo("/tmp", null, null, "/tmp", CertificateFormat.BASE_64, "psw", "alias");
        try {
            certificateManager.checkCertificateValidity(ksInfo, subj, cmEnt, false, cmPib);
            assertTrue(true);
        } catch (final CertificateValidationException e) {
            assertTrue(false);
        }
    }

    /**
     * @return
     */
    private CredentialManagerPIBParameters getMockPIBParameters() {
        final CredentialManagerPIBParameters parameters = new CredentialManagerPIBParameters();
        parameters.setServiceCertAutoRenewalEnabled(true);
        parameters.setServiceCertAutoRenewalTimer(2);
        parameters.setServiceCertAutoRenewalWarnings("20,10,5");
        return parameters;
    }

    @Test
    public void testIsCertificateValid() {

        final CertificateManager certificateManager = new CertificateManager(null);

        /**
         * Retrieve Certificate
         */
        final String certPassword = "keyStorePwd";
        final String certAlias = "Test";
        FileInputStream fis = null;
        KeyStore certKeystore;
        Certificate certificate = null;

        /*
         * Certificate generation and storage
         */
        final CertificateManager certificateManagerMock = new CertificateManager(mockedWrapper);

        final List<KeystoreInfo> testKeyStoreInfo = CertificateWriter.writeKeyAndCertificateJKS(certificateManagerMock,
                CertificateWriter.CertMode.valid);

        final String certStoreName = testKeyStoreInfo.get(0).getKeyAndCertLocation();
        // load the keystore
        final File file = new File(certStoreName);
        try {
            certKeystore = KeyStore.getInstance(StorageConstants.JKS_STORE_TYPE);
            if (!file.exists()) {
                assertTrue("File not found!", false);
            } else {
                fis = new FileInputStream(file);
                certKeystore.load(fis, certPassword.toCharArray());
                fis.close();
                certificate = (certKeystore.getCertificateChain(certAlias))[0];
            }
        } catch (final Exception e) {
            assertTrue("Exception not expected during certificate build-up", false);
        } finally {
            File kfile = new File("/tmp/keyAndCertTest.jks");
            if(kfile.exists()) {
                assertTrue(kfile.delete());
            }
        }

        /**
         * Setting of expected parameters
         */
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setName("myEntity");
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        final String subject = "CN=CN";

        final CredentialManagerProfileInfo profileInfo = PrepareCertificate.prepareProfileInfo();

        /**
         * Testcases
         */
        /**
         * Wrong IssuerName
         */
        final String originalIssuerName = profileInfo.getIssuerName();
        final CredentialManagerSubject issuerDN = new CredentialManagerSubject();
        entity.setIssuerDN(issuerDN.updateFromSubjectDN("CN=wrong " + originalIssuerName));
        try {
            if (certificateManager.isCertificateValid(certificate, subject, entity, true, getMockPIBParameters())) {
                assertTrue("testIsCertificateValid failed!", false);
            } else {
                assertTrue("testIsCertificateValid ok!", true);
            }
        } catch (final CertificateValidationException e) {
            assertTrue("Unexpected Exception!", false);
        }

        /**
         * Restore correct DN
         */
        entity.setIssuerDN(issuerDN.updateFromSubjectDN(originalIssuerName));

        /**
         * wrong subject (LDAP format)
         */
        try {
            if (certificateManager.isCertificateValid(certificate, "O=OpenDJ, CN=Unknown", entity, true, getMockPIBParameters())) {
                assertTrue("testIsCertificateValid failed!", false);
            } else {
                assertTrue("testIsCertificateValid ok!", true);
            }
        } catch (final CertificateValidationException e) {
            assertTrue("Unexpected Exception!", false);
        }

        /**
         * wrong subject (no LDAP)
         */
        try {
            assertTrue(certificateManager.isCertificateValid(certificate, "wrongSubject", entity, true, getMockPIBParameters()));
        } catch (final CertificateValidationException e) {
            if (e.getMessage().contains("Invalid name")) {
                assertTrue(true);
            } else {
                assertTrue("testIsCertificateValid failed!", false);
            }
        }

        /**
         * REISSUE status
         */
        entity.setEntityStatus(CredentialManagerEntityStatus.REISSUE);
        try {
            certificateManager.isCertificateValid(certificate, subject, entity, true, getMockPIBParameters());
            assertTrue(certificateManager.getRevokeCertId() != null);

        } catch (final CertificateValidationException e) {
            assertTrue("Unexpected Exception!", false);
        }

        //
        // MOCKED wrapper

        final CertificateManager mockedCertificateManager = new CertificateManager(this.mockedWrapper);

        /**
         * test execution with status=ACTIVE
         */
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        final List<CredentialManagerX509Certificate> certList = new ArrayList<CredentialManagerX509Certificate>();
        CredentialManagerX509Certificate x509Cert = null;
        try {
            x509Cert = new CredentialManagerX509Certificate((X509Certificate) certificate);
        } catch (final CertificateEncodingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        certList.add(x509Cert);

        when(this.mockedWrapper.getMode()).thenReturn(channelMode.SECURE_CHANNEL);
        when(this.mockedWrapper.listActiveCertificates(Matchers.anyString())).thenReturn(certList);
        try {
            final Boolean result = mockedCertificateManager.isCertificateValid(certificate, subject, entity, true, getMockPIBParameters());
            assertTrue("isCertificateValid", result);
        } catch (final CertificateValidationException e) {
            assertTrue("testIsCertificateValid failed!", false);
        } catch (final Exception e) {
            assertTrue("testIsCertificateValid unexpected exception!", false);
        }
    }

    @Test
    public void isCertificateValidTestFails() throws CertificateValidationException {
        final CertificateManager certificateManager = new CertificateManager(null);
        final String subj = "CN=CN";
        final CredentialManagerEntity cmEnt = new CredentialManagerEntity();
        cmEnt.setName("isCertFailEntity");
        cmEnt.setEntityStatus(CredentialManagerEntityStatus.NEW); //default to be sure
        final CredentialManagerSubject cmSubj = new CredentialManagerSubject();
        final CredentialManagerSubject issuerSubj = new CredentialManagerSubject();
        cmSubj.setCommonName("CN");
        issuerSubj.updateFromSubjectDN("C=Unknown, ST=Unknown, L=Unknown, O=ericsson, OU=ericsson, CN=rootCA");
        cmEnt.setIssuerDN(issuerSubj);
        final CredentialManagerPIBParameters cmPib = new CredentialManagerPIBParameters();

        //fail and fake log with service sysrec cause of certificate expired (will exit with entity status NEW)
        final Certificate certExp = PrepareCertificate.prepareExpiredCertificate(PrepareCertificate.createKeyPair());
        cmPib.setServiceCertAutoRenewalEnabled(false);
        Mockito.doNothing().when(mockRmiClient).printErrorOnRecorder("Certificate Expired", ErrorSeverity.WARNING, "Credential Manager CLI",
                "isCertFailEntity", "AutoRenewal is not set");
        final CertificateManager mockedCertificateManager = new CertificateManager(this.mockedWrapper);
        assertTrue(!mockedCertificateManager.isCertificateValid(certExp, subj, cmEnt, false, cmPib));

        //Inactive entity: it means someone revoked the active certificate and never reissued one
        final Certificate cert = PrepareCertificate.prepareCertificate(PrepareCertificate.createKeyPair());
        cmEnt.setEntityStatus(CredentialManagerEntityStatus.INACTIVE);
        assertTrue(!certificateManager.isCertificateValid(cert, subj, cmEnt, false, cmPib));

        //it should never occur, however it returns true (it does not reissue a cert for a deleted entity)
        cmEnt.setEntityStatus(CredentialManagerEntityStatus.DELETED);
        assertTrue(certificateManager.isCertificateValid(cert, subj, cmEnt, false, cmPib));

        cmEnt.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        cmEnt.setName("noActiveCertificatesEntity");
        when(this.mockedWrapper.getMode()).thenReturn(channelMode.SECURE_CHANNEL);
        when(this.mockedWrapper.listActiveCertificates("noActiveCertificatesEntity")).thenReturn(null);//to cover if null instead of empt list
        assertTrue(!mockedCertificateManager.isCertificateValid(cert, subj, cmEnt, false, cmPib));

        //Check different serial number
        final Certificate differentCert = PrepareCertificate.prepareCertificate();
        X509Certificate X509diffCert = null;
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            final InputStream inputStream = new ByteArrayInputStream(differentCert.getEncoded());
            X509diffCert = (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (final CertificateException e) {
            throw (new CertificateValidationException("isCertificateValidTest: " + e.getMessage()));
        }
        CredentialManagerX509Certificate cmX509diffCert;
        try {
            cmX509diffCert = new CredentialManagerX509Certificate(X509diffCert);
        } catch (final CertificateEncodingException e) {
            throw (new CertificateValidationException("isCertificateValidTest: " + e.getMessage()));
        }
        final List<CredentialManagerX509Certificate> returnedList = new ArrayList<CredentialManagerX509Certificate>();
        returnedList.add(cmX509diffCert);
        cmEnt.setName("OneActiveCertificatesEntity");
        when(this.mockedWrapper.listActiveCertificates("OneActiveCertificatesEntity")).thenReturn(returnedList);
        assertTrue(!mockedCertificateManager.isCertificateValid(cert, subj, cmEnt, true, cmPib));
    }

    @Test
    public void testGenerateWrongCSR() {

        final CertificateManager certificateManager = new CertificateManager(null);
        final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();
        profileInfo.setIssuerName("CN=ENM PKI Root CA");

        final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();
        subjectAltName.getIpaddress().add(0, "1.1.1.1");
        final CredentialManagerSubjectAlternateName credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(subjectAltName);

        final CredentialManagerAlgorithm algorithm = new CredentialManagerAlgorithm();
        profileInfo.setKeyPairAlgorithm(algorithm);
        profileInfo.getKeyPairAlgorithm().setName("RSA");
        profileInfo.getKeyPairAlgorithm().setKeySize(2048);
        profileInfo.setIssuerName("CN=ENM PKI Root CA");

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("CN=pippo");
        entity.setEntityStatus(CredentialManagerEntityStatus.NEW);

        final Map<String, Attribute> attributes = new HashMap<String, Attribute>();
        attributes.put(Extension.subjectAlternativeName.toString(), credMsubjAltName.getAttribute());

        final CredentialManagerCertificateExtension certificateExtensionInfo = new CredentialManagerCertificateExtensionImpl();
        certificateExtensionInfo.setAttributes(attributes);

        try {
            certificateManager.generateCSR(entity, profileInfo, certificateExtensionInfo);
        } catch (final Exception e) {
            assertTrue("testGenerateCSR", true);
            return;
        }
        assertTrue("testGenerateCSR", false);
    }

    @Test
    public void testGenerateCertificateMock() throws CredentialManagerCertificateEncodingException, CredentialManagerEntityNotFoundException,
            CredentialManagerCertificateGenerationException, CredentialManagerInvalidCSRException, CredentialManagerInvalidEntityException,
            CredentialManagerCertificateExsitsException {

        final CertificateManager certificateManager = new CertificateManager(this.mockWrapper);

        final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();
        profileInfo.setIssuerName("CN=ENM PKI Root CA");

        final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();
        subjectAltName.getIpaddress().add(0, "1.1.1.1");
        final CredentialManagerSubjectAlternateName credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(subjectAltName);

        final CredentialManagerAlgorithm algorithm = new CredentialManagerAlgorithm();
        profileInfo.setKeyPairAlgorithm(algorithm);
        profileInfo.getKeyPairAlgorithm().setName("RSA");
        profileInfo.getKeyPairAlgorithm().setKeySize(2048);

        /**
         * KEYS
         */
        try {
            certificateManager.generateKey(profileInfo);
            assertTrue("KeyPair is null", certificateManager.getKeyPair() != null);
        } catch (final IssueCertificateException e) {
            assertTrue("testGenerateCertificateMock failed (KeyPair not generated)", false);
        }

        algorithm.setKeySize(2048);
        algorithm.setName("SHA256WithRSAEncryption");
        profileInfo.setSignatureAlgorithm(algorithm);

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("OAM Entity");
        entity.setEntityStatus(CredentialManagerEntityStatus.NEW);
        entity.setName("DN=pippo");

        final List<String> subAltNameList = new ArrayList<String>();
        subAltNameList.add("ipaddress=1.1.1.1");
        final CredentialManagerSubjectAltName cmAltSubName = new CredentialManagerSubjectAltName();
        cmAltSubName.setIPAddress(subAltNameList);

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setCommonName("CN=altro");

        entity.setSubjectAltName(cmAltSubName);
        entity.setSubject(subject);

        /**
         * Null CSR
         */
        try {
            certificateManager.generateCertificate("pippo", profileInfo, false, null);
            assertTrue("Exception not originated", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception expected", true);
        } catch (final OtpExpiredException e) {
            assertTrue(false);
        } catch (final OtpNotValidException e) {
            assertTrue(false);
        }

        /**
         * CSR
         */
        final Map<String, Attribute> attributes = new HashMap<String, Attribute>();
        attributes.put(Extension.subjectAlternativeName.toString(), credMsubjAltName.getAttribute());

        final CredentialManagerCertificateExtension certificateExtensionInfo = new CredentialManagerCertificateExtensionImpl();
        certificateExtensionInfo.setSubjectAlternativeName("subjectAlternativeName"); // minOccurs=1
        certificateExtensionInfo.setAttributes(attributes);

        try {
            certificateManager.generateCSR(entity, profileInfo, certificateExtensionInfo);
        } catch (final IssueCertificateException e) {
            assertTrue("testGenerateCertificateMock failed (CSR not generated)", false);
        }

        when(mockRmiClient.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.eq("wrongEntityName"), Matchers.eq(true),
                Matchers.eq("fakeOTP"))).thenReturn(null);
        try {
            certificateManager.generateCertificate("wrongEntityName", profileInfo, true, "fakeOTP");
            assertTrue(false);
        } catch (final IssueCertificateException e) {
            assertTrue(true);
        } catch (final OtpExpiredException e) {
            assertTrue(false);
        } catch (final OtpNotValidException e) {
            assertTrue(false);
        }

        /**
         * CERT
         */
        final X509Certificate caCert = PrepareCertificate.prepareCertificate();
        CredentialManagerX509Certificate CMcaCert = null;
        CredentialManagerX509Certificate[] CMcaCertChain = null;

        /*
         * Generate certificate without Chain
         */
        try {

            CMcaCert = new CredentialManagerX509Certificate(caCert);
            CMcaCertChain = new CredentialManagerX509Certificate[] { CMcaCert };

            when(mockRmiClient.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.eq(false),
                    Matchers.anyString())).thenReturn(CMcaCertChain);
            //certificateManager.generateCertificate("DN=pippo", profileInfo);
            certificateManager.generateCertificate("pippo", profileInfo, false, null);
        } catch (final IssueCertificateException | CertificateEncodingException | OtpExpiredException | OtpNotValidException e) {
            assertTrue("testGenerateCertificateMock failed (certificate not generated)", false);
        }

        /*
         * Generate certificate with Chain
         */
        try {

            CMcaCert = new CredentialManagerX509Certificate(caCert);
            CMcaCertChain = new CredentialManagerX509Certificate[] { CMcaCert };

            when(mockRmiClient.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.eq(true),
                    Matchers.anyString())).thenReturn(CMcaCertChain);
            certificateManager.generateCertificate("pippo", profileInfo, true, null);
        } catch (final IssueCertificateException | CertificateEncodingException | OtpExpiredException | OtpNotValidException e) {
            assertTrue("testGenerateCertificateMock failed (certificate with chain not generated)", false);
        }

        /**
         * Switch channel to REST (by use of reflection)
         */
        Field modeField;
        try {
            modeField = this.mockWrapper.getClass().getDeclaredField("mode");
            modeField.setAccessible(true);
            modeField.set(this.mockWrapper, CredMServiceWrapper.channelMode.REST_CHANNEL);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e1) {
            assertTrue("testGenerateCertificateMock failed (Reflection error)", false);
        }

        try {
            when(mockRestCLient.getCertificate(Matchers.any(PKCS10CertificationRequest.class))).thenReturn(CMcaCertChain);
            certificateManager.generateCertificateRestChannel();
        } catch (final Exception e) {
            assertTrue("testGenerateCertificateMock failed (generateCertificateRestChannel)", false);
        }

        try {
            when(mockRestCLient.getCertificate(Matchers.any(PKCS10CertificationRequest.class))).thenReturn(null);
            certificateManager.generateCertificateRestChannel();
            assertTrue("testGenerateCertificateMock: Exception not originated", false);
        } catch (final IssueCertificateException e) {
            assertTrue("testGenerateCertificateMock: Exception expected", true);
        }
    }

    @Test
    public void testWriteKeyAndCertificate() {

        /*
         * Create KeyPair parameter
         */
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        final X509Certificate cert = PrepareCertificate.prepareCertificate(keyPair);

        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/keyAndCertTest.jks", "", "", null, CertificateFormat.JKS, "keyStorePwd", "Test");
        ksInfoList.add(ksInfo);

        final CertificateManager certificateManager = new CertificateManager(null);

        certificateManager.setKeyPair(keyPair);
        certificateManager.setCertChain(new Certificate[] { cert });
        certificateManager.setCertHandler(new CertHandler());

        try {
            certificateManager.writeKeyAndCertificate(ksInfoList);
        } catch (final IssueCertificateException e) {
            e.printStackTrace();
            assertTrue("testWriteKeyAndCertificate: writeKeyAndCertificate failed", false);
        }
        assertTrue("testWriteKeyAndCertificate: ok", true);

        certificateManager.clearKeystores(ksInfoList);
        assertTrue("testWriteKeyAndCertificate: deleteKeystores ok", true);
    }

    @Test
    public void testWriteKeyAndCertificateKeyPairNull() {

        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/keyAndCertTest.jks", "", "", null, CertificateFormat.JKS, "keyStorePwd", "Test");
        ksInfoList.add(ksInfo);

        final CertificateManager certificateManager = new CertificateManager(null);

        try {
            certificateManager.writeKeyAndCertificate(ksInfoList);
        } catch (final IssueCertificateException e) {
            assertTrue("testWriteKeyAndCertificateKeyPairNull: passed", true);
            File kfile = new File("/tmp/keyAndCertTest.jks");
            if(kfile.exists()) {
                assertTrue(kfile.delete());
            }
            return;
        }
        assertTrue("testWriteKeyAndCertificateKeyPairNull: failed", false);
    }

    @Test
    public void testWriteKeyAndCertificateCertChainNull() {
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/keyAndCertTest.jks", "", "", null, CertificateFormat.JKS, "keyStorePwd", "Test");
        ksInfoList.add(ksInfo);

        final CertificateManager certificateManager = new CertificateManager(null);

        certificateManager.setKeyPair(keyPair);

        try {
            certificateManager.writeKeyAndCertificate(ksInfoList);
        } catch (final IssueCertificateException e) {
            assertTrue("testWriteKeyAndCertificateCertChainNull: passed", true);
            File kfile = new File("/tmp/keyAndCertTest.jks");
            if(kfile.exists()) {
                assertTrue(kfile.delete());
            }
            return;
        }
        assertTrue("testWriteKeyAndCertificateCertChainNull: failed", false);
    }

    @Test
    public void testWriteKeyAndCertificateCertHandlerNull() {
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        final X509Certificate cert = PrepareCertificate.prepareCertificate(keyPair);

        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/keyAndCertTest.jks", "", "", null, CertificateFormat.JKS, "keyStorePwd", "Test");
        ksInfoList.add(ksInfo);

        final CertificateManager certificateManager = new CertificateManager(null);

        certificateManager.setKeyPair(keyPair);
        certificateManager.setCertChain(new Certificate[] { cert });

        try {
            certificateManager.writeKeyAndCertificate(ksInfoList);
            assertTrue("testWriteKeyAndCertificateCertHandlerNull: failed", false);
        } catch (final IssueCertificateException e) {
            assertTrue("testWriteKeyAndCertificateCertHandlerNull: passed", true);
        }

        final CertHandler mockCertHandler = Mockito.mock(CertHandler.class);
        try {
            Mockito.doThrow(new CertHandlerException()).when(mockCertHandler).writeKeyAndCertificate(certificateManager.getCertChain(), keyPair,
                    ksInfo);
        } catch (final CertHandlerException e1) {
            assertTrue(false);
        }
        certificateManager.setCertHandler(mockCertHandler);
        try {
            certificateManager.writeKeyAndCertificate(ksInfoList);
            assertTrue(false);
        } catch (final IssueCertificateException e) {
            File kfile = new File("/tmp/keyAndCertTest.jks");
            if(kfile.exists()) {
                assertTrue(kfile.delete());
            }
            assertTrue(true);
        }

    }

    @Test
    public void testRevokeCertificate() {

        final CertificateManager certificateManager = new CertificateManager(mockWrapper);

        certificateManager.setRevokeCertId(null);
        assertTrue("revokeCertificate failed", certificateManager.revokeCertificate() == null);

        final X500Principal xmlSubject = new X500Principal("CN=xmlSubject");
        final X500Principal issuerDN = new X500Principal("CN=issuerDN");
        final BigInteger certId = new BigInteger("12345");
        final CredentialManagerCertificateIdentifier revokeCertId = new CredentialManagerCertificateIdentifier(xmlSubject, issuerDN, certId);
        certificateManager.setRevokeCertId(revokeCertId);
        Mockito.doNothing().when(mockRmiClient).revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class),
                Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));

        assertTrue("revokeCertificate failed", certificateManager.revokeCertificate());
    }

    @Test
    public void testGenerateCertificateRestChannelNullCsr() {

        final CertificateManager certificateManager = new CertificateManager(null);

        try {
            certificateManager.generateCertificateRestChannel();
            assertTrue("Exception not occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Expected exception", true);
        }
    }

    @Test
    public void testGenerateKeyPairFail() {
        final CertificateManager certificateManager = new CertificateManager(null);
        final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();
        final CredentialManagerAlgorithm algorithm = new CredentialManagerAlgorithm();
        algorithm.setKeySize(911);
        algorithm.setName("fakeAlgorithm");
        profileInfo.setKeyPairAlgorithm(algorithm);
        final CredentialManagerSubject subjectByProfile = new CredentialManagerSubject();
        subjectByProfile.setDnQualifier("dnQualifier");
        profileInfo.setSubjectByProfile(subjectByProfile);
        try {
            certificateManager.generateKey(profileInfo);
            assertTrue(false);
        } catch (final IssueCertificateException e) {
            assertTrue(certificateManager.getKeyPair() == null);
        }
    }

}
