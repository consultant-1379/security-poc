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
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.ProfileManager;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.ejb.CredMServiceBean;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.credmservice.util.CertificateUtils;
import com.ericsson.oss.itpf.security.credmservice.util.StorageFilesInformation;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;
import com.ericsson.oss.services.security.pkimock.util.X509CACertificateGenerator;

@RunWith(MockitoJUnitRunner.class)
public class CredMServiceSelfCredentialsManagerTest {

    @Mock
    CredMServiceBean credMService;

    @Mock
    ProfileManager profileManager;

    @Mock
    CredMServiceStartupConfBean credMServiceStartupConfBean;

    @InjectMocks
    CredMServiceSelfCredentialsManager credMServiceSelfCredentialsManager;

    @Mock
    private SystemRecorderWrapper systemRecorder;

    private void setup(final boolean validTrust, final boolean validKeyPairAlg, final boolean validCert, final String validProfile,
                       final String validEntity)
            throws DatatypeConfigurationException, CredentialManagerServiceException {
        try {
            final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();

            final CredentialManagerSubject subjectByProfile = new CredentialManagerSubject();
            subjectByProfile.setOrganizationName("Ericsson");
            profileInfo.setSubjectByProfile(subjectByProfile);

            final CredentialManagerSubjectAltName subjectAltName = new CredentialManagerSubjectAltName();
            final List<String> directoryName = new ArrayList();
            directoryName.add("directoryName");
            subjectAltName.setDirectoryName(directoryName);
            profileInfo.setSubjectDefaultAlternativeName(subjectAltName);

            final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
            keyGenerationAlgorithm.setKeySize(2048);
            if (validKeyPairAlg) {
                keyGenerationAlgorithm.setName("RSA");
            } else {
                keyGenerationAlgorithm.setName("InvalidKeyAlgorithm");
            }
            profileInfo.setKeyPairAlgorithm(keyGenerationAlgorithm);

            final CredentialManagerAlgorithm signatureAlgorithm = new CredentialManagerAlgorithm();
            signatureAlgorithm.setName("SHA256WithRSAEncryption");// Da mettere
            // giusto
            profileInfo.setSignatureAlgorithm(signatureAlgorithm);

            final String issuer = "CN=ENMManagementCA";
            final Duration validity = DatatypeFactory.newInstance().newDuration("P365D");
            profileInfo.setIssuerName(issuer);

            final String profileName = "credMServiceProfile";

            if (validProfile.equals("validProfile")) {
                when(this.profileManager.getProfile(profileName)).thenReturn(profileInfo);
            } else if (validProfile.equals("invalidProfile")) {
                when(this.profileManager.getProfile(profileName)).thenThrow(new CredentialManagerInternalServiceException());
            } else {
                when(this.profileManager.getProfile(profileName)).thenReturn(null);
            }
            final CredentialManagerEntity entity = new CredentialManagerEntity();
            subjectByProfile.setCommonName("CREDMService");
            entity.setSubject(subjectByProfile);

            String hostname = null;
            try {
                hostname = InetAddress.getLocalHost().getHostName();
            } catch (final UnknownHostException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            final String entityName = "JbossSPS_" + hostname;
            entity.setName(entityName);

            if (validEntity.equals("validEntity")) {

                when(this.credMService.createAndGetEntity(entityName, subjectByProfile, subjectAltName, keyGenerationAlgorithm, profileName)).thenReturn(entity);

            } else if (validEntity.equals("invalidEntity")) {
                when(this.credMService.createAndGetEntity(entityName, subjectByProfile, subjectAltName, keyGenerationAlgorithm, profileName))
                        .thenThrow(new CredentialManagerInternalServiceException());
            } else {
                when(this.credMService.createAndGetEntity(entityName, subjectByProfile, subjectAltName, keyGenerationAlgorithm, profileName))
                        .thenReturn(null);
            }
            PKCS10CertificationRequest csr;
            CredentialManagerX509Certificate certificate = null;
            if (validKeyPairAlg) {

                final KeyPair keyPair = KeyGenerator.getKeyPair(profileInfo.getKeyPairAlgorithm().getName(), profileInfo.getKeyPairAlgorithm().getKeySize());


                csr = CertificateUtils.generatePKCS10Request(profileInfo.getSignatureAlgorithm().getName(), entity, keyPair, null,
                        BouncyCastleProvider.PROVIDER_NAME);

                final X509Certificate cert = X509CACertificateGenerator.generateCertificateFromCA(csr, issuer, validity);
                certificate = new CredentialManagerX509Certificate(cert.getEncoded());
                final CredentialManagerX509Certificate[] certificateChain = new CredentialManagerX509Certificate[] { certificate };
                if (validCert) {

                    when(this.credMService.getCertificate(any(CredentialManagerPKCS10CertRequest.class), eq(entityName), eq(false), Matchers.anyString())).thenReturn(certificateChain);
                    // inserted chain in the CredMService certificate in order to manage reissue of certificates with reKey 
                    when(this.credMService.getCertificate(any(CredentialManagerPKCS10CertRequest.class), eq(entityName), eq(true), Matchers.anyString())).thenReturn(certificateChain);
                } else {
                    when(this.credMService.getCertificate(any(CredentialManagerPKCS10CertRequest.class), eq(entityName), eq(false), Matchers.anyString())).thenThrow(
                            new CredentialManagerCertificateGenerationException());
                    // inserted chain in the CredMService certificate in order to manage reissue of certificates with reKey 
                    when(this.credMService.getCertificate(any(CredentialManagerPKCS10CertRequest.class), eq(entityName), eq(true), Matchers.anyString())).thenThrow(
                            new CredentialManagerCertificateGenerationException());

                }
            }
            final CredentialManagerTrustMaps trustMaps = new CredentialManagerTrustMaps();
            //final Map<String, CredentialManagerCertificateAuthority> trusts = new HashMap();
            final CredentialManagerCertificateAuthority ca = new CredentialManagerCertificateAuthority(issuer);
            final List<CredentialManagerX509Certificate> caList = new ArrayList();
            caList.add(certificate);
            ca.setCertChainSerializable(caList);
            //trusts.put(issuer, ca);
            trustMaps.getInternalCATrustMap().put(issuer, ca);

            if (validTrust) {
                when(this.credMService.getTrustCertificates(profileName)).thenReturn(trustMaps);
            } else {
                when(this.credMService.getTrustCertificates(profileName)).thenThrow(new CredentialManagerInternalServiceException());
            }
            StorageFilesInformation.outputPath = "/tmp";

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (final CertificateEncodingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
    }

    private void clean() {
        final File file = new File("/tmp/CredMService.jks");

        if (file.delete()) {
            System.out.println(file.getName() + " is deleted!");
        } else {
            System.out.println("Delete operation is failed.");
        }

        final File file2 = new File("/tmp/CredMServiceTS.jks");

        if (file2.delete()) {
            System.out.println(file2.getName() + " is deleted!");
        } else {
            System.out.println("Delete operation is failed.");
        }

    }

    @Test
    public void testGenerateJBossCredentials() throws CredentialManagerStartupException, FileNotFoundException, DatatypeConfigurationException {

        try {
            this.setup(true, true, true, "validProfile", "validEntity");

        } catch (final CredentialManagerServiceException e) {

            throw new CredentialManagerStartupException(e.getMessage());
        }
        this.credMServiceSelfCredentialsManager.generateJBossCredentials();

        final InputStream in = new FileInputStream("/tmp/CredMService.jks");

        assertNotNull(in);

        final InputStream in2 = new FileInputStream("/tmp/CredMServiceTS.jks");

        assertNotNull(in2);

        this.clean();

    }

    @Test
    public void testGetTrustFailOnGenerateJBssCredentials() {
        try {
            this.setup(false, true, true, "validProfile", "validEntity");

        } catch (DatatypeConfigurationException | CredentialManagerServiceException e) {

            assertTrue(false);
        }
        try {
            this.credMServiceSelfCredentialsManager.generateJBossCredentials();
            assertTrue(false);
        } catch (final CredentialManagerStartupException e) {
            assertTrue(true);
        }

        try {
            final InputStream in = new FileInputStream("/tmp/CredMService.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }

        try {
            final InputStream in2 = new FileInputStream("/tmp/CredMServiceTS.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }
        this.clean();
    }

    @Test
    public void testGenKeyFailOnGenerateJBssCredentials() {
        try {
            this.setup(true, false, true, "validProfile", "validEntity");

        } catch (DatatypeConfigurationException | CredentialManagerServiceException e) {

            assertTrue(false);
        }
        try {
            this.credMServiceSelfCredentialsManager.generateJBossCredentials();
            assertTrue(false);
        } catch (final CredentialManagerStartupException e) {
            assertTrue(true);
        }

        try {
            final InputStream in = new FileInputStream("/tmp/CredMService.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }

        try {
            final InputStream in2 = new FileInputStream("/tmp/CredMServiceTS.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }
        this.clean();
    }

    @Test
    public void testGetCertFailOnGenerateJBssCredentials() {
        try {
            this.setup(true, true, false, "validProfile", "validEntity");

        } catch (DatatypeConfigurationException | CredentialManagerServiceException e) {

            assertTrue(false);
        }
        try {
            this.credMServiceSelfCredentialsManager.generateJBossCredentials();
            assertTrue(false);
        } catch (final CredentialManagerStartupException e) {
            assertTrue(true);
        }

        try {
            final InputStream in = new FileInputStream("/tmp/CredMService.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }

        try {
            final InputStream in2 = new FileInputStream("/tmp/CredMServiceTS.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }
        this.clean();
    }

    @Test
    public void testGetProfileFailOnGenerateJBssCredentials() {
        try {
            this.setup(true, true, true, "invalidProfile", "validEntity");

        } catch (DatatypeConfigurationException | CredentialManagerServiceException e) {

            assertTrue(false);
        }
        try {
            this.credMServiceSelfCredentialsManager.generateJBossCredentials();
            assertTrue(false);
        } catch (final CredentialManagerStartupException e) {
            assertTrue(true);
        }

        try {
            final InputStream in = new FileInputStream("/tmp/CredMService.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }

        try {
            final InputStream in2 = new FileInputStream("/tmp/CredMServiceTS.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }
        this.clean();
    }

    @Test
    public void testGetProfileNullOnGenerateJBssCredentials() {
        try {
            this.setup(true, true, true, "null", "validEntity");

        } catch (DatatypeConfigurationException | CredentialManagerServiceException e) {

            assertTrue(false);
        }
        try {
            this.credMServiceSelfCredentialsManager.generateJBossCredentials();
            assertTrue(false);
        } catch (final CredentialManagerStartupException e) {
            assertTrue(true);
        }

        try {
            final InputStream in = new FileInputStream("/tmp/CredMService.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }

        try {
            final InputStream in2 = new FileInputStream("/tmp/CredMServiceTS.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }
        this.clean();
    }

    @Test
    public void testGetEntityFailOnGenerateJBssCredentials() {
        try {
            this.setup(true, true, true, "validProfile", "invalidEntity");

        } catch (DatatypeConfigurationException | CredentialManagerServiceException e) {

            assertTrue(false);
        }
        try {
            this.credMServiceSelfCredentialsManager.generateJBossCredentials();
            assertTrue(false);
        } catch (final CredentialManagerStartupException e) {
            assertTrue(true);
        }

        try {
            final InputStream in = new FileInputStream("/tmp/CredMService.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }

        try {
            final InputStream in2 = new FileInputStream("/tmp/CredMServiceTS.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }
        this.clean();
    }

    @Test
    public void testGetEntityNullOnGenerateJBssCredentials() {
        try {
            this.setup(true, true, true, "validProfile", "null");

        } catch (DatatypeConfigurationException | CredentialManagerServiceException e) {

            assertTrue(false);
        }
        try {
            this.credMServiceSelfCredentialsManager.generateJBossCredentials();
            assertTrue(false);
        } catch (final CredentialManagerStartupException e) {
            assertTrue(true);
        }

        try {
            final InputStream in = new FileInputStream("/tmp/CredMService.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }

        try {
            final InputStream in2 = new FileInputStream("/tmp/CredMServiceTS.jks");
            assertTrue(false);
        } catch (final FileNotFoundException e) {
            assertTrue(true);
        }
        this.clean();
    }

    @Test
    public void testcheckJbossEntityReissueStateActive() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setName("Jboss");
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        when(this.credMService.getEntity(any(String.class))).thenReturn(entity);

        assertTrue(this.credMServiceSelfCredentialsManager.checkJbossEntityReissueState());
    }

    @Test
    public void testcheckJbossEntityReissueStateReissue() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setName("Jboss");
        entity.setEntityStatus(CredentialManagerEntityStatus.REISSUE);
        when(this.credMService.getEntity(any(String.class))).thenReturn(entity);

        assertFalse(this.credMServiceSelfCredentialsManager.checkJbossEntityReissueState());
    }

    @Test
    public void testcheckJbossEntityReissueStateNull() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(this.credMService.getEntity(any(String.class))).thenReturn(null);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        this.credMServiceSelfCredentialsManager.checkJbossEntityReissueState();
    }

    @Test
    public void testcheckJbossEntityReissueStateReturnCredentialManagerEntityNotFoundException() throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(this.credMService.getEntity(any(String.class))).thenThrow(CredentialManagerEntityNotFoundException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkJbossEntityReissueState());
    }

    @Test
    public void testcheckJbossEntityReissueStateReturnCredentialManagerInternalServiceException() throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(this.credMService.getEntity(any(String.class))).thenThrow(CredentialManagerInternalServiceException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkJbossEntityReissueState());
    }

    @Test
    public void testcheckJbossEntityReissueStateReturnCredentialManagerInvalidEntityException() throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(this.credMService.getEntity(any(String.class))).thenThrow(CredentialManagerInvalidEntityException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkJbossEntityReissueState());
    }

    @Test
    public void testcheckJbossEntityReissueStateReturnCredentialManagerInvalidArgumentException() throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(this.credMService.getEntity(any(String.class))).thenThrow(CredentialManagerInvalidArgumentException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkJbossEntityReissueState());
    }

    @Test
    public void testcheckJbossCheckTrustsReturnCredentialManagerProfileNotFoundException()
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers = credMServiceSelfCredentialsManager.readTrustsFromKeystore();
        when(this.credMService.compareTrustAndRetrieve("credMServiceProfile", currentTrustIdentifiers, true, true))
                .thenThrow(CredentialManagerProfileNotFoundException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkTrusts());
    }

    @Test
    public void testcheckJbossCheckTrustsReturnCredentialManagerInternalServiceException()
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers = credMServiceSelfCredentialsManager.readTrustsFromKeystore();
        when(this.credMService.compareTrustAndRetrieve("credMServiceProfile", currentTrustIdentifiers, true, true))
                .thenThrow(CredentialManagerInternalServiceException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkTrusts());
    }

    @Test
    public void testcheckJbossCheckTrustsReturnCredentialManagerCertificateEncodingException()
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers = credMServiceSelfCredentialsManager.readTrustsFromKeystore();
        when(this.credMService.compareTrustAndRetrieve("credMServiceProfile", currentTrustIdentifiers, true, true))
                .thenThrow(CredentialManagerCertificateEncodingException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkTrusts());
    }

    @Test
    public void testcheckJbossCheckTrustsReturnCredentialManagerInvalidArgumentException()
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers = credMServiceSelfCredentialsManager.readTrustsFromKeystore();
        when(this.credMService.compareTrustAndRetrieve("credMServiceProfile", currentTrustIdentifiers, true, true))
                .thenThrow(CredentialManagerInvalidArgumentException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkTrusts());
    }

    @Test
    public void testcheckJbossCheckTrustsReturnCredentialManagerInvalidProfileException()
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers = credMServiceSelfCredentialsManager.readTrustsFromKeystore();
        when(this.credMService.compareTrustAndRetrieve("credMServiceProfile", currentTrustIdentifiers, true, true))
                .thenThrow(CredentialManagerInvalidProfileException.class);
        Mockito.doNothing().when(this.systemRecorder).recordError(any(String.class), any(ErrorSeverity.class), any(String.class), any(String.class),
                any(String.class));
        assertTrue(this.credMServiceSelfCredentialsManager.checkTrusts());
    }

    @Test
    public void testcheckJbossCheckTrustsReturnOk() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers = credMServiceSelfCredentialsManager.readTrustsFromKeystore();
        when(this.credMService.compareTrustAndRetrieve("credMServiceProfile", currentTrustIdentifiers, true, true)).thenReturn(null);
        assertTrue(this.credMServiceSelfCredentialsManager.checkTrusts());
    }

    @Test
    public void testcheckJbossCheckTrustsReturnNotOk() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers = credMServiceSelfCredentialsManager.readTrustsFromKeystore();
        when(this.credMService.compareTrustAndRetrieve("credMServiceProfile", currentTrustIdentifiers, true, true))
                .thenReturn(new CredentialManagerTrustMaps());
        assertTrue(!this.credMServiceSelfCredentialsManager.checkTrusts());
        assertTrue(!this.credMServiceSelfCredentialsManager.checkTrustValidity());
    }
}
