/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.ejb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.security.auth.x500.X500Principal;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.CertificateManager;
import com.ericsson.oss.itpf.security.credmservice.api.CertificateManagerPki;
import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerAlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerOtpExpiredException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCALists;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.api.model.exception.CRLEncodingException;
import com.ericsson.oss.itpf.security.credmservice.configuration.listener.CredentialManagerConfigurationListener;
import com.ericsson.oss.itpf.security.credmservice.impl.PKIModelMapper;
import com.ericsson.oss.itpf.security.credmservice.impl.ProfileManagerImpl;
import com.ericsson.oss.itpf.security.credmservice.util.JKSReader;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.UnsupportedCRLVersionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.services.security.pkimock.api.MockEntityManagementService;
import com.ericsson.oss.services.security.pkimock.util.CertificateUtils;
import com.ericsson.oss.services.security.pkimock.util.X509CACertificateGenerator;

@RunWith(MockitoJUnitRunner.class)

public class CredMServiceBeanTest {

    @Mock
    ProfileManagerImpl profileManager;

    @Mock
    MockEntityManagementService mockEntityManagerService;

    @Mock
    CertificateManager certificateManager;

    @Spy
    @InjectMocks
    CertificateManagerPki certificateManagerPki = new CertificateManagerPkiBean();

    @Mock
    CredMRestAvailability credMPkiConfBean;

    @InjectMocks
    CredMServiceBean credMServiceBean;

    @Mock
    CredentialManagerConfigurationListener credentialManagerConfigurationListener;

    @Test
    public void createAndGetEndEntityTestForUpdate() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=Paola");

        final CredentialManagerSubjectAltName subjectAltName = new CredentialManagerSubjectAltName();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("paolaProfile");
        entity.setSubject(subject);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        when(profileManager.getEntity("paolaEE")).thenReturn(entity);
        when(profileManager.updateEntity("paolaEE", subject, subjectAltName, keyGenerationAlgorithm, "paolaProfile")).thenReturn(entity)
                .thenThrow(new CredentialManagerEntityNotFoundException());
        when(profileManager.isEntityPresent("paolaEE")).thenReturn(true);

        final CredentialManagerEntity entityReturned = credMServiceBean.createAndGetEntity("paolaEE", subject, subjectAltName,
                keyGenerationAlgorithm, "paolaProfile");

        assertNotNull(entityReturned);
        assertEquals("paolaProfile", entityReturned.getEntityProfileName());
        assertEquals("Paola", entityReturned.getSubject().getCommonName());

        final CredentialManagerEntity entityNull = credMServiceBean.createAndGetEntity("paolaEE", subject, subjectAltName,
                keyGenerationAlgorithm, "paolaProfile");
        assertTrue(entityNull == null);
    }

    @Test
    public void createAndGetEndEntityFailedTestForUpdate() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=Paola");

        final CredentialManagerSubjectAltName subjectAltName = new CredentialManagerSubjectAltName();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("paolaProfile");
        entity.setSubject(subject);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        final Entity pkiEntity = new Entity();
        final EntityInfo pkiEntityInfo = new EntityInfo();
        final EntityProfile pkiEntityProfile = new EntityProfile();
        pkiEntityInfo.setId(7777);
        pkiEntityInfo.setName("paolaEntity");

        final Subject pkiSubject = new Subject();
        final Map<SubjectFieldType, String> subjectDN = new HashMap<SubjectFieldType, String>();
        subjectDN.put(SubjectFieldType.COMMON_NAME, "paola");

        for (final Entry<SubjectFieldType, String> entry : subjectDN.entrySet()) {
            final SubjectField subFieldTemp = new SubjectField();
            subFieldTemp.setType(entry.getKey());
            subFieldTemp.setValue(entry.getValue());
            pkiSubject.getSubjectFields().add(subFieldTemp);
        }

        pkiEntityInfo.setSubject(pkiSubject);
        pkiEntity.setEntityInfo(pkiEntityInfo);
        pkiEntity.setEntityProfile(pkiEntityProfile);
        pkiEntity.getEntityProfile().setName("paolaProfileName");

        when(profileManager.getEntity("paolaEE")).thenReturn(entity);

        try {
            when(mockEntityManagerService.getEntity(Matchers.any(AbstractEntity.class))).thenReturn(pkiEntity);
        } catch (EntityNotFoundException | EntityServiceException | InvalidEntityException | InvalidEntityAttributeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            when(mockEntityManagerService.updateEntity(Matchers.any(AbstractEntity.class))).thenThrow(new EntityServiceException());
        } catch (InvalidSubjectAltNameExtension | InvalidSubjectException | MissingMandatoryFieldException | AlgorithmNotFoundException
                | EntityCategoryNotFoundException | InvalidEntityCategoryException | CRLExtensionException | CRLGenerationException
                | EntityAlreadyExistsException | EntityNotFoundException | EntityServiceException | InvalidCRLGenerationInfoException
                | InvalidEntityException | InvalidEntityAttributeException | InvalidProfileException | ProfileNotFoundException
                | UnsupportedCRLVersionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        when(profileManager.updateEntity("paolaEE", subject, subjectAltName, keyGenerationAlgorithm, "paolaProfile"))
                .thenThrow(new CredentialManagerInvalidEntityException());

        final CredentialManagerEntity entityReturned = credMServiceBean.createAndGetEntity("paolaEE", subject, subjectAltName,
                keyGenerationAlgorithm, "paolaProfile");

        assertNull(entityReturned);
    }

    @Test
    public void createAndGetEndEntityTestForCreate() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=Paola");

        final CredentialManagerSubjectAltName subjectAltName = new CredentialManagerSubjectAltName();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("paolaProfile");
        entity.setSubject(subject);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        when(profileManager.getEntity("paolaEE")).thenReturn(null);
        when(profileManager.createEntity("paolaEE", subject, subjectAltName, keyGenerationAlgorithm, "paolaProfile")).thenReturn(entity);

        final CredentialManagerEntity entityReturned = credMServiceBean.createAndGetEntity("paolaEE", subject, subjectAltName,
                keyGenerationAlgorithm, "paolaProfile");

        assertNotNull(entityReturned);
        assertEquals("paolaProfile", entityReturned.getEntityProfileName());
        assertEquals("Paola", entityReturned.getSubject().getCommonName());

        final CredentialManagerEntity entityCreated = credMServiceBean.createEntity("eName", new CredentialManagerSubject(),
                new CredentialManagerSubjectAltName(), new CredentialManagerAlgorithm(), "eProfile");
        assertTrue(entityCreated == null);
    }

    @Test(expected = CredentialManagerInvalidEntityException.class)
    public void createAndGetEndEntityFailedTestForCreate() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=Paola");

        final CredentialManagerSubjectAltName subjectAltName = new CredentialManagerSubjectAltName();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("paolaProfile");
        entity.setSubject(subject);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        when(profileManager.getEntity("paolaEE")).thenThrow(new CredentialManagerEntityNotFoundException());
        when(profileManager.createEntity("paolaEE", subject, subjectAltName, keyGenerationAlgorithm, "paolaProfile"))
                .thenThrow(new CredentialManagerInvalidEntityException());

        final CredentialManagerEntity entityReturned = credMServiceBean.createAndGetEntity("paolaEE", subject, subjectAltName,
                keyGenerationAlgorithm, "paolaProfile");

        // assertNull(entityReturned);
    }

    @Test
    public void getEndEntityTest() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=Paola");

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("paolaProfile");
        entity.setSubject(subject);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        when(profileManager.getEntity("paolaEE")).thenReturn(entity);

        final CredentialManagerEntity entityReturned = credMServiceBean.getEntity("paolaEE");

        assertNotNull(entityReturned);
        assertEquals("paolaProfile", entityReturned.getEntityProfileName());
        assertEquals("Paola", entityReturned.getSubject().getCommonName());
    }

    @Test(expected = CredentialManagerInvalidEntityException.class)
    public void getEndEntityFailedTest() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=Paola");

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("paolaProfile");
        entity.setSubject(subject);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        when(profileManager.getEntity("paolaEE")).thenThrow(new CredentialManagerInvalidEntityException());

        final CredentialManagerEntity entityReturned = credMServiceBean.getEntity("paolaEE");

        // assertNull(entityReturned);
    }

    @Test
    public void getProfileTest() throws CredentialManagerServiceException {

        final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();
        profileInfo.setIssuerName("CN=ENMManagementCA");

        when(profileManager.getProfile("paolaProfile")).thenReturn(profileInfo);
        when(credMPkiConfBean.isEnabled()).thenReturn(true);

        final CredentialManagerProfileInfo profileInfoReturned = credMServiceBean.getProfile("paolaProfile");

        assertNotNull(profileInfoReturned);
        assertEquals("CN=ENMManagementCA", profileInfoReturned.getIssuerName());

        when(credMPkiConfBean.isEnabled()).thenReturn(false);
        CredentialManagerProfileInfo profileInfoNotReturned = null;
        try {
            profileInfoNotReturned = credMServiceBean.getProfile("paolaProfile");
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(profileInfoNotReturned == null);
        }
    }

    @Test(expected = CredentialManagerProfileNotFoundException.class)
    public void getProfileFailedTest() throws CredentialManagerServiceException {

        final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();
        profileInfo.setIssuerName("CN=ENMManagementCA");

        when(profileManager.getProfile("paolaProfile")).thenThrow(new CredentialManagerProfileNotFoundException());
        when(credMPkiConfBean.isEnabled()).thenReturn(true);

        final CredentialManagerProfileInfo profileInfoReturned = credMServiceBean.getProfile("paolaProfile");

        // assertNull(profileInfoReturned);
    }

    @Test
    public void getCertificateTest()
            throws CredentialManagerServiceException, CertificateException, DatatypeConfigurationException, CertificateServiceException {

        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);
        final PKCS10CertificationRequest csr = createCSR(keyPair);
        CredentialManagerPKCS10CertRequest csrHolder = null;
        try {
            csrHolder = new CredentialManagerPKCS10CertRequest(csr);
        } catch (final IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        final String issuer = "CN=ENMManagementCA";
        final Duration validity = DatatypeFactory.newInstance().newDuration("P356D");

        final X509Certificate cert = X509CACertificateGenerator.generateCertificateFromCA(csr, issuer, validity);
        final com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate pkicert =
                new com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate();
        pkicert.setX509Certificate(cert);

        final CredentialManagerX509Certificate[] cert1 = new CredentialManagerX509Certificate[] { PKIModelMapper.credMCertificateFrom(pkicert) };

        /*
         * Test certificate without Chain
         */
        when(certificateManager.getCertificate(csrHolder, "entityName", false, null)).thenReturn(cert1);
        final CredentialManagerX509Certificate[] certificateReturned = credMServiceBean.getCertificate(csrHolder, "entityName", false, null);

        assertNotNull(certificateReturned);

        // We just test the case of an array with one single certificate inside
        assertEquals("O=Ericsson,OU=EricssonOAM,CN=ENMManagementCA", certificateReturned[0].retrieveCertificate().getIssuerDN().getName());
        assertEquals("RSA", certificateReturned[0].retrieveCertificate().getPublicKey().getAlgorithm());
        assertEquals("CN=mara", certificateReturned[0].retrieveCertificate().getSubjectDN().getName());
        assertEquals("SHA256WITHRSA", certificateReturned[0].retrieveCertificate().getSigAlgName());

        /*
         * Test certificate with Chain
         */
        final PKCS10CertificationRequest csrForCA = createCSRForCA(keyPair);
        final String issuer2 = "CN=ENMInfrastructureCA";

        final X509Certificate cert2 = X509CACertificateGenerator.generateCertificateFromCA(csrForCA, issuer2, validity);
        final com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate pkicert2 =
                new com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate();
        pkicert2.setX509Certificate(cert2);

        final CredentialManagerX509Certificate[] certChainArray = new CredentialManagerX509Certificate[] {
            PKIModelMapper.credMCertificateFrom(pkicert), PKIModelMapper.credMCertificateFrom(pkicert2) };

        when(certificateManager.getCertificate(csrHolder, "entityName", true, null)).thenReturn(certChainArray);
        final CredentialManagerX509Certificate[] certificateChainReturned = credMServiceBean.getCertificate(csrHolder, "entityName", true, null);

        assertNotNull(certificateChainReturned);

        assertTrue("Certificate chain length is not greater than 1", certificateChainReturned.length > 1);

    }

    @Test(expected = CredentialManagerCertificateGenerationException.class)
    public void getCertificateFailedTestForCredentialManagerCertificateGenerationException() throws CredentialManagerServiceException {

        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);
        final PKCS10CertificationRequest csr = createCSR(keyPair);
        CredentialManagerPKCS10CertRequest csrHolder;
        try {
            csrHolder = new CredentialManagerPKCS10CertRequest(csr);
        } catch (final IOException e) {
            throw new CredentialManagerCertificateServiceException();
        }
        final String issuer = "CN=ENMManagementCA";
        final int validity = 365;

        when(certificateManager.getCertificate(csrHolder, "entityName", false, null))
                .thenThrow(new CredentialManagerCertificateGenerationException());

        final CredentialManagerX509Certificate[] certificateReturned = credMServiceBean.getCertificate(csrHolder, "entityName", false, null);

        // assertNull(certificateReturned);
    }

    @Test(expected = CredentialManagerCertificateEncodingException.class)
    public void getCertificateFailedTestForCertificateEncodingException() throws CredentialManagerServiceException {

        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);
        final PKCS10CertificationRequest csr = createCSR(keyPair);
        CredentialManagerPKCS10CertRequest csrHolder;
        try {
            csrHolder = new CredentialManagerPKCS10CertRequest(csr);
        } catch (final IOException e) {
            throw new CredentialManagerCertificateServiceException();
        }
        final String issuer = "CN=ENMManagementCA";

        when(certificateManager.getCertificate(csrHolder, "entityName", false, null))
                .thenThrow(new CredentialManagerCertificateEncodingException());

        final CredentialManagerX509Certificate[] certificateReturned = credMServiceBean.getCertificate(csrHolder, "entityName", false, null);

        // assertNull(certificateReturned);
    }

    @Test
    public void getTrustCertificatesTest() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final CredentialManagerTrustMaps trustMaps = credMServiceBean.getTrustCertificates("paolaProfile");

        assertNotNull(trustMaps);
    }

    @Test
    public void getTrustCertificatesWithComparationOKTest() throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final CredentialManagerTrustCA trustIntCA = new CredentialManagerTrustCA("scrooge", false);
        final CredentialManagerTrustCA trustExtCA = new CredentialManagerTrustCA("scroogeExternal", false);
        final CredentialManagerCertificateAuthority internalCAs = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                "pippoTrustInt");
        when(certificateManager.getTrustCertificates(trustIntCA, false)).thenReturn(internalCAs);
        final CredentialManagerCertificateAuthority externalCAs = getCredMCAs("CredMServiceBeanTest/trusts/CredMServiceTS.jks", "pippoTrustExt");
        when(certificateManager.getTrustCertificates(trustExtCA, true)).thenReturn(externalCAs);
        final CredentialManagerCALists value = new CredentialManagerCALists();
        value.getInternalCAList().add(trustIntCA);
        value.getExternalCAList().add(trustExtCA);
        when(profileManager.getTrustCAList("scroogeProfile")).thenReturn(value);

        final CredentialManagerTrustMaps trustMaps = credMServiceBean.getTrustCertificates("scroogeProfile");
        final SortedSet<CredentialManagerCertificateIdentifier> certIds = new TreeSet<CredentialManagerCertificateIdentifier>();
        extractCertIds(trustMaps, certIds);
        final CredentialManagerTrustMaps result = credMServiceBean.compareTrustAndRetrieve("scroogeProfile", certIds, true, true);

        assertTrue(result == null);
    }

    @Test
    public void getTrustCertificatesWithComparationNOTOKMoreTest()
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final CredentialManagerTrustCA trustIntCA = new CredentialManagerTrustCA("scrooge", false);
        final CredentialManagerTrustCA trustExtCA = new CredentialManagerTrustCA("scroogeExternal", false);
        final CredentialManagerCertificateAuthority internalCAs = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                "pippoTrustInt");
        when(certificateManager.getTrustCertificates(trustIntCA, false)).thenReturn(internalCAs);
        final CredentialManagerCertificateAuthority externalCAs = getCredMCAs("CredMServiceBeanTest/trusts/CredMServiceTS.jks", "pippoTrustExt");
        when(certificateManager.getTrustCertificates(trustExtCA, true)).thenReturn(externalCAs);
        final CredentialManagerCALists value = new CredentialManagerCALists();
        value.getInternalCAList().add(trustIntCA);
        value.getExternalCAList().add(trustExtCA);
        when(profileManager.getTrustCAList("scroogeProfile")).thenReturn(value);
        final CredentialManagerCALists value2 = new CredentialManagerCALists();
        value2.getInternalCAList().add(trustIntCA);
        when(profileManager.getTrustCAList("scroogeProfile2")).thenReturn(value2);

        final CredentialManagerTrustMaps trustMaps = credMServiceBean.getTrustCertificates("scroogeProfile2");
        final SortedSet<CredentialManagerCertificateIdentifier> certIds = new TreeSet<CredentialManagerCertificateIdentifier>();
        extractCertIds(trustMaps, certIds);
        final CredentialManagerTrustMaps result = credMServiceBean.compareTrustAndRetrieve("scroogeProfile2", certIds, false, true);

        assertTrue(result != null);

    }

    @Test
    public void getTrustCertificatesWithComparationNOTOKLessTest()
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final CredentialManagerCertificateAuthority internalCAs = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                "pippoTrustInt");
        final CredentialManagerTrustCA trustIntCA = new CredentialManagerTrustCA("scrooge", false);
        when(certificateManager.getTrustCertificates(trustIntCA, false)).thenReturn(internalCAs);
        final CredentialManagerCertificateAuthority externalCAs = getCredMCAs("CredMServiceBeanTest/trusts/CredMServiceTS.jks", "pippoTrustExt");
        final CredentialManagerTrustCA trustExtCA = new CredentialManagerTrustCA("scroogeExternal", false);
        when(certificateManager.getTrustCertificates(trustExtCA, true)).thenReturn(externalCAs);
        final CredentialManagerCALists value = new CredentialManagerCALists();
        value.getInternalCAList().add(trustIntCA);
        value.getExternalCAList().add(trustExtCA);
        when(profileManager.getTrustCAList("scroogeProfile")).thenReturn(value);
        final CredentialManagerCALists value2 = new CredentialManagerCALists();
        value2.getInternalCAList().add(trustIntCA);
        when(profileManager.getTrustCAList("scroogeProfile2")).thenReturn(value2);

        final CredentialManagerTrustMaps trustMaps = credMServiceBean.getTrustCertificates("scroogeProfile");
        final SortedSet<CredentialManagerCertificateIdentifier> certIds = new TreeSet<CredentialManagerCertificateIdentifier>();
        extractCertIds(trustMaps, certIds);
        final CredentialManagerTrustMaps result = credMServiceBean.compareTrustAndRetrieve("scroogeProfile", certIds, true, true);

        assertTrue(result == null);
    }

    @Ignore
    @Test
    public void getTrustCertificatesWithComparationNOTOKDifferentTest()
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final CredentialManagerCertificateAuthority internalCAs = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                "pippoTrustInt");
        when(certificateManager.getTrustCertificates(new CredentialManagerTrustCA("scrooge", false), false)).thenReturn(internalCAs);
        final CredentialManagerCertificateAuthority externalCAs = getCredMCAs("CredMServiceBeanTest/trusts/CredMServiceTS.jks", "pippoTrustExt");
        when(certificateManager.getTrustCertificates(new CredentialManagerTrustCA("scroogeExternal", false), true)).thenReturn(externalCAs);
        final CredentialManagerCALists value = new CredentialManagerCALists();
        value.getInternalCAList().add(new CredentialManagerTrustCA("scroogeExternal", false));
        when(profileManager.getTrustCAList("scroogeProfile")).thenReturn(value);
        final CredentialManagerCALists value2 = new CredentialManagerCALists();
        value2.getInternalCAList().add(new CredentialManagerTrustCA("scrooge", false));
        when(profileManager.getTrustCAList("scroogeProfile2")).thenReturn(value2);

        final CredentialManagerTrustMaps trustMaps = credMServiceBean.getTrustCertificates("scroogeProfile2");
        final SortedSet<CredentialManagerCertificateIdentifier> certIds = new TreeSet<CredentialManagerCertificateIdentifier>();
        extractCertIds(trustMaps, certIds);

        final CredentialManagerTrustMaps result = credMServiceBean.compareTrustAndRetrieve("scroogeProfile2", certIds, true, true);

        assertTrue(result != null);
    }

    @Test
    public void getTrustCertificatesUsingTrustProfileOK() throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final CredentialManagerTrustCA trustIntCA = new CredentialManagerTrustCA("scrooge", false);
        final CredentialManagerTrustCA trustExtCA = new CredentialManagerTrustCA("scroogeExternal", false);
        final CredentialManagerCertificateAuthority internalCAs = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                "pippoTrustInt");
        when(certificateManager.getTrustCertificates(trustIntCA, false)).thenReturn(internalCAs);
        final CredentialManagerCertificateAuthority externalCAs = getCredMCAs("CredMServiceBeanTest/trusts/CredMServiceTS.jks", "pippoTrustExt");
        when(certificateManager.getTrustCertificates(trustExtCA, true)).thenReturn(externalCAs);
        final CredentialManagerCALists value = new CredentialManagerCALists();
        value.getInternalCAList().add(trustIntCA);
        value.getExternalCAList().add(trustExtCA);
        when(profileManager.getTrustCAListFromTP("scroogeProfile", null)).thenReturn(value);

        final CredentialManagerTrustMaps trustMaps = credMServiceBean.getTrustCertificatesTP("scroogeProfile");
        final SortedSet<CredentialManagerCertificateIdentifier> certIds = new TreeSet<CredentialManagerCertificateIdentifier>();
        extractCertIds(trustMaps, certIds);
        final CredentialManagerTrustMaps result = credMServiceBean.compareTrustAndRetrieveTP("scroogeProfile", certIds, true, true);

        assertTrue(result == null);
    }

    @Test
    public void getTrustCertificatesUsingTrustProfileNotOK() throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final CredentialManagerTrustCA trustIntCA = new CredentialManagerTrustCA("scrooge", false);
        final CredentialManagerTrustCA trustExtCA = new CredentialManagerTrustCA("scroogeExternal", false);
        final CredentialManagerCertificateAuthority internalCAs = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                "pippoTrustInt");
        when(certificateManager.getTrustCertificates(trustIntCA, false)).thenReturn(internalCAs);
        final CredentialManagerCertificateAuthority externalCAs = getCredMCAs("CredMServiceBeanTest/trusts/CredMServiceTS.jks", "pippoTrustExt");
        when(certificateManager.getTrustCertificates(trustExtCA, true)).thenReturn(externalCAs);
        final CredentialManagerCALists value = new CredentialManagerCALists();
        value.getInternalCAList().add(trustIntCA);
        // value.getExternalCAList().add("scroogeExternal");
        when(profileManager.getTrustCAListFromTP("scroogeProfile", null)).thenReturn(value);

        final CredentialManagerTrustMaps trustMaps = credMServiceBean.getTrustCertificatesTP("scroogeProfile");
        final SortedSet<CredentialManagerCertificateIdentifier> certIds = new TreeSet<CredentialManagerCertificateIdentifier>();
        extractCertIds(trustMaps, certIds);
        final CredentialManagerTrustMaps result = credMServiceBean.compareTrustAndRetrieveTP("scroogeProfile", certIds, false, true);

        assertTrue(result != null);
        try {
            credMServiceBean.compareTrustAndRetrieveTP("scroogeProfile", null, false, true);
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }
    }

    @Test
    public void getTrustCertificatesSameCerts() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerServiceException {
        final CredentialManagerCALists value = new CredentialManagerCALists();
        final CredentialManagerTrustCA trustExtCA = new CredentialManagerTrustCA("extScrooge", false);
        final CredentialManagerTrustCA trustIntCA1 = new CredentialManagerTrustCA("intScrooge1", true);
        final CredentialManagerTrustCA trustIntCA2 = new CredentialManagerTrustCA("intScrooge2", true);
        value.getExternalCAList().add(trustExtCA);
        value.getInternalCAList().add(trustIntCA1);
        value.getInternalCAList().add(trustIntCA2);
        when(profileManager.getTrustCAList("scroogeProfile")).thenReturn(value);
        final CredentialManagerCertificateAuthority internalCAs1 = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                trustIntCA1.getTrustCAName());
        final CredentialManagerCertificateAuthority internalCAs2 = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                trustIntCA2.getTrustCAName());
        final CredentialManagerCertificateAuthority externalCAs = getCredMCAs("CredMServiceBeanTest/trusts/CredMServiceTS.jks",
                trustExtCA.getTrustCAName());
        when(certificateManager.getTrustCertificates(trustExtCA, true)).thenReturn(externalCAs);
        when(certificateManager.getTrustCertificates(trustIntCA1, false)).thenReturn(internalCAs1);
        when(certificateManager.getTrustCertificates(trustIntCA2, false)).thenReturn(internalCAs2);

        CredentialManagerTrustMaps trustMaps = credMServiceBean.getTrustCertificates("scroogeProfile");
        assertTrue(trustMaps.getExternalCATrustMap().get(trustExtCA.getTrustCAName()).equals(externalCAs));
        // There are 2 internal ca, but they are init with the same certificates.
        // So, to avoid duplicates only one will appear in the end
        assertTrue(trustMaps.getInternalCATrustMap().size() == 1);

        trustIntCA1.setChainRequired(false);
        trustIntCA2.setTrustCAName(trustIntCA1.getTrustCAName());
        trustIntCA2.setChainRequired(false);

        trustMaps = credMServiceBean.getTrustCertificates("scroogeProfile");
        assertTrue(trustMaps.getExternalCATrustMap().get(trustExtCA.getTrustCAName()).equals(externalCAs));
        // The same, but in this case the second internal CA will be entirely skipped
        assertTrue(trustMaps.getInternalCATrustMap().size() == 1);

    }

    @Test(expected = CertificateNotFoundException.class)
    public void getTrustCertificatesWithCertificateNotFoundExceptionInExternalCA()
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {
        final CredentialManagerCALists value = new CredentialManagerCALists();
        final CredentialManagerTrustCA trustExtCA = new CredentialManagerTrustCA("extScrooge", false);
        final CredentialManagerTrustCA trustIntCA1 = new CredentialManagerTrustCA("intScrooge1", true);
        value.getExternalCAList().add(trustExtCA);
        value.getInternalCAList().add(trustIntCA1);
        when(profileManager.getTrustCAList("scroogeProfile")).thenReturn(value);
        final CredentialManagerCertificateAuthority internalCAs1 = getCredMCAs("CredMServiceBeanTest/trusts/ENMManagementCA-chain.jks",
                trustIntCA1.getTrustCAName());
        when(certificateManager.getTrustCertificates(trustExtCA, true)).thenThrow(new CertificateNotFoundException());
        when(certificateManager.getTrustCertificates(trustIntCA1, false)).thenReturn(internalCAs1);

        credMServiceBean.getTrustCertificates("scroogeProfile");
    }

    /**
     * @param trustMaps
     * @param certIds
     */
    private void extractCertIds(final CredentialManagerTrustMaps trustMaps, final SortedSet<CredentialManagerCertificateIdentifier> certIds) {
        for (final CredentialManagerCertificateAuthority certa : trustMaps.getExternalCATrustMap().values()) {
            for (final CredentialManagerX509Certificate cert : certa.getCACertificateChain()) {
                final X509Certificate x509Cert = cert.retrieveCertificate();
                final CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(x509Cert.getSubjectX500Principal(),
                        x509Cert.getIssuerX500Principal(), x509Cert.getSerialNumber());
                certIds.add(certId);
            }
        }

        for (final CredentialManagerCertificateAuthority certa : trustMaps.getInternalCATrustMap().values()) {
            for (final CredentialManagerX509Certificate cert : certa.getCACertificateChain()) {
                final X509Certificate x509Cert = cert.retrieveCertificate();
                final CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(x509Cert.getSubjectX500Principal(),
                        x509Cert.getIssuerX500Principal(), x509Cert.getSerialNumber());
                certIds.add(certId);
            }
        }
    }

    @Test
    public void getCRLsTest() throws CredentialManagerServiceException {
        final CredentialManagerCrlMaps crlMap = credMServiceBean.getCRLs("paolaProfile", true);

        assertNotNull(crlMap);
    }

    @Test
    public void getEntityByCategoryTest() throws CredentialManagerServiceException {

        // first test: empty list
        final Set<CredentialManagerEntity> entityReturned1 = credMServiceBean.getEntitiesByCategory("SERVICE");
        assertNotNull(entityReturned1);
        assertTrue("getEntitiesByCategory", entityReturned1.size() == 0);

        // mockito data preparation
        final Set<CredentialManagerEntity> entitySetMock = new HashSet<CredentialManagerEntity>();
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=Paola");
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("paolaProfile");
        entity.setSubject(subject);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        entity.setEntityStatus(CredentialManagerEntityStatus.NEW);
        entitySetMock.add(entity);
        when(profileManager.getEntitiesByCategory("pippo")).thenReturn(entitySetMock);

        // second test: mockito
        final Set<CredentialManagerEntity> entityReturned2 = credMServiceBean.getEntitiesByCategory("pippo");
        assertNotNull(entityReturned2);
        assertTrue("getEntitiesByCategory", entityReturned2.size() == 1);
        final Iterator<CredentialManagerEntity> iter = entityReturned2.iterator();
        final CredentialManagerEntity firstEntity = iter.next();

        assertEquals("paolaProfile", firstEntity.getEntityProfileName());
        assertEquals("Paola", firstEntity.getSubject().getCommonName());
        assertEquals(CredentialManagerEntityStatus.NEW, firstEntity.getEntityStatus());

        // third test: throw exception
        when(profileManager.getEntitiesByCategory("pluto")).thenThrow(CredentialManagerInvalidArgumentException.class);
        try {
            final Set<CredentialManagerEntity> entityReturned3 = credMServiceBean.getEntitiesByCategory("pluto");
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }

    }

    @Test
    public void getEntitySummaryByCategoryTest() throws CredentialManagerServiceException {

        // first test: empty list
        final Set<CredentialManagerEntity> entityReturned1 = credMServiceBean.getEntitiesSummaryByCategory("SERVICE");
        assertNotNull(entityReturned1);
        assertTrue("getEntitiesSummaryByCategory", entityReturned1.size() == 0);

        // mockito data preparation
        final Set<CredentialManagerEntity> entitySetMock = new HashSet<CredentialManagerEntity>();
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=Paola");
        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityProfileName("paolaProfile");
        entity.setSubject(subject);
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        entity.setEntityStatus(CredentialManagerEntityStatus.NEW);
        entitySetMock.add(entity);
        when(profileManager.getEntitiesSummaryByCategory("pippo")).thenReturn(entitySetMock);

        // second test: mockito
        final Set<CredentialManagerEntity> entityReturned2 = credMServiceBean.getEntitiesSummaryByCategory("pippo");
        assertNotNull(entityReturned2);
        assertTrue("getEntitiesSummaryByCategory", entityReturned2.size() == 1);
        final Iterator<CredentialManagerEntity> iter = entityReturned2.iterator();
        final CredentialManagerEntity firstEntity = iter.next();

        assertEquals("Paola", firstEntity.getSubject().getCommonName());
        assertEquals(CredentialManagerEntityStatus.NEW, firstEntity.getEntityStatus());

        // third test: throw exception
        when(profileManager.getEntitiesSummaryByCategory("pluto")).thenThrow(CredentialManagerInvalidArgumentException.class);
        try {
            final Set<CredentialManagerEntity> entityReturned3 = credMServiceBean.getEntitiesSummaryByCategory("pluto");
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }

    }

    @Test
    public void isOtpValidFalseTest()
            throws CredentialManagerEntityNotFoundException, CredentialManagerOtpExpiredException, CredentialManagerInternalServiceException {
        when(profileManager.isOTPValid("pippo", "otp")).thenReturn(false);
        try {
            final boolean result = credMServiceBean.isOTPValid("pippo", "otp");
            assertTrue(!result);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue("Exception not expected", false);
        } catch (final CredentialManagerOtpExpiredException e) {
            assertTrue("Exception not expected", false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue("Exception not expected", false);
        }
    }

    @Test
    public void isOtpValidExceptionTest()
            throws CredentialManagerEntityNotFoundException, CredentialManagerOtpExpiredException, CredentialManagerInternalServiceException {
        when(profileManager.isOTPValid("pippo", "otp")).thenThrow(new CredentialManagerOtpExpiredException());
        try {
            credMServiceBean.isOTPValid("pippo", "otp");
            assertTrue(false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue("Exception not expected", false);
        } catch (final CredentialManagerOtpExpiredException e) {
            assertTrue("Exception not expected", true);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue("Exception not expected", false);
        }
    }

    @Test
    public void revokeCertificatebyEntityTest() throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException {

        final CredentialManagerRevocationReason reason = CredentialManagerRevocationReason.UNSPECIFIED;
        final Date date = new Date();
        credMServiceBean.revokeCertificateByEntity("pippo", reason, date);

    }

    @Test
    public void revokeCertificatebyCertIdTest() throws CredentialManagerInternalServiceException, CredentialManagerCertificateNotFoundException,
            CredentialManagerExpiredCertificateException, CredentialManagerAlreadyRevokedCertificateException {
        final CredentialManagerRevocationReason reason = CredentialManagerRevocationReason.UNSPECIFIED;
        final Date date = new Date();
        final X500Principal subjDN = new X500Principal("CN=Pippo");
        final X500Principal issuerDN = new X500Principal("CN=PlutoCA");

        final CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(subjDN, issuerDN, new BigInteger("" + 10));
        credMServiceBean.revokeCertificateById(certId, reason, date);
    }

    @Test
    public void listCertificatesTest() throws CredentialManagerInternalServiceException, CredentialManagerCertificateNotFoundException,
            CredentialManagerCertificateServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException,
            CredentialManagerCertificateEncodingException {
        List<CredentialManagerX509Certificate> certs;
        certs = credMServiceBean.listCertificates("pippo", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
        assertTrue(certs.isEmpty());

        when(certificateManager.ListCertificates("CertNotFound", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE))
                .thenThrow(CredentialManagerCertificateNotFoundException.class);
        certs = credMServiceBean.listCertificates("CertNotFound", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
        assertTrue(certs.isEmpty());

        when(certificateManager.ListCertificates("serviceError", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE))
                .thenThrow(CredentialManagerCertificateServiceException.class);
        try {
            certs = credMServiceBean.listCertificates("serviceError", CredentialManagerEntityType.ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(certs.isEmpty());
        }

    }

    @Test
    public void getVersionTest() {
        final String version = credMServiceBean.getVersion();
        assertEquals(credMServiceBean.CMSERVICE_VERSION, version);
    }

    @Test
    public void printCommandOnRecorderTest() {

        try {
            credMServiceBean.printCommandOnRecorder(null, CommandPhase.STARTED, null, null, null);
            assertTrue(false);
        } catch (final IllegalArgumentException e) {
            assertTrue(true);
        }

        try {
            credMServiceBean.printCommandOnRecorder("testCommandOk", CommandPhase.STARTED, "junit", "pippo", null);
            assertTrue(true);
        } catch (final IllegalArgumentException e) {
            assertTrue(false);
        }
    }

    @Test
    public void printErrorOnRecorderTest() {

        try {
            credMServiceBean.printErrorOnRecorder(null, ErrorSeverity.INFORMATIONAL, null, null, null);
            assertTrue(false);
        } catch (final IllegalArgumentException e) {
            assertTrue(true);
        }

        try {
            credMServiceBean.printErrorOnRecorder("testErrorOk", ErrorSeverity.INFORMATIONAL, "junit", "pippo", null);
            assertTrue(true);
        } catch (final IllegalArgumentException e) {
            assertTrue(false);
        }

    }

    @Test
    public void helloTest() {
        final String msg = "PAOLA";
        final String hello = credMServiceBean.hello(msg);
        assertEquals("Hi PAOLA, nice to meet you, I'm Credential Manager Service", hello);
    }

    @Test
    public void getPibParameterTest() {

        try {
            final CredentialManagerPIBParameters parameters = credMServiceBean.getPibParameters();
            assertTrue(true);
        } catch (final IllegalArgumentException e) {
            assertTrue(false);
        }

    }

    @Test
    public void listCertificatesSummaryTest() throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException {

        final List<CredentialManagerX500CertificateSummary> credManx500CertsSummaryList = new ArrayList<CredentialManagerX500CertificateSummary>();

        final X500Principal subjectFirst = new X500Principal("CN=subjectFirst");
        final X500Principal issuerFirst = new X500Principal("CN=issuerFirst");
        final BigInteger certificateSnFirst = new BigInteger("123456788");
        final CredentialManagerCertificateStatus certStatusFirst = CredentialManagerCertificateStatus.ACTIVE;
        final CredentialManagerX500CertificateSummary credManCertSummaryFirst = new CredentialManagerX500CertificateSummary(subjectFirst, issuerFirst,
                certificateSnFirst, certStatusFirst);

        final X500Principal subjectSecond = new X500Principal("CN=subjectSecond");
        final X500Principal issuerSecond = new X500Principal("CN=issuerSecond");
        final BigInteger certificateSnSecond = new BigInteger("123456789");
        final CredentialManagerCertificateStatus certStatusSecond = CredentialManagerCertificateStatus.INACTIVE;
        final CredentialManagerX500CertificateSummary credManCertSummarySecond = new CredentialManagerX500CertificateSummary(subjectSecond,
                issuerSecond, certificateSnSecond, certStatusSecond);

        credManx500CertsSummaryList.add(credManCertSummaryFirst);
        credManx500CertsSummaryList.add(credManCertSummarySecond);

        //// first check
        when(certificateManager.listCertificatesSummary("AnyEntity", CredentialManagerEntityType.ENTITY,
                CredentialManagerCertificateStatus.ACTIVE, CredentialManagerCertificateStatus.INACTIVE)).thenReturn(credManx500CertsSummaryList);
        List<CredentialManagerX500CertificateSummary> firstCheck = null;
        try {
            firstCheck = credMServiceBean.listCertificatesSummary("AnyEntity", CredentialManagerEntityType.ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE, CredentialManagerCertificateStatus.INACTIVE);
        } catch (final Exception e) {
            assertTrue("first check: Exception not expected", false);
        }
        assertTrue("first check: returned list is null", firstCheck != null);
        assertTrue("first check: returned list has wrong size", firstCheck.size() == 2);
        assertTrue("first check: firt certif. retrieved NOT OK",
                firstCheck.get(0).getCertificateStatus().equals(CredentialManagerCertificateStatus.ACTIVE));
        assertTrue("first check: second certif. retrieved NOT OK",
                firstCheck.get(1).getIssuerX500Principal().getName().equalsIgnoreCase("CN=issuerSecond"));

        //// second check
        when(certificateManager.listCertificatesSummary("CertNotFound", CredentialManagerEntityType.ENTITY,
                CredentialManagerCertificateStatus.ACTIVE, CredentialManagerCertificateStatus.INACTIVE))
                        .thenThrow(CredentialManagerCertificateNotFoundException.class);
        try {
            final List<CredentialManagerX500CertificateSummary> secondCheck = credMServiceBean.listCertificatesSummary("CertNotFound",
                    CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE, CredentialManagerCertificateStatus.INACTIVE);
            assertTrue("An Exception has not been thrown", false);
        } catch (final CredentialManagerCertificateNotFoundException e) {
            assertTrue(true);
        } catch (final Exception e) {
            assertTrue("CredentialManagerCertificateNotFoundException was expected", false);
        }

        //// third check
        when(certificateManager.listCertificatesSummary("EntityNotFound", CredentialManagerEntityType.ENTITY,
                CredentialManagerCertificateStatus.ACTIVE, CredentialManagerCertificateStatus.INACTIVE))
                        .thenThrow(CredentialManagerEntityNotFoundException.class);
        try {
            final List<CredentialManagerX500CertificateSummary> thirdCheck = credMServiceBean.listCertificatesSummary("EntityNotFound",
                    CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE, CredentialManagerCertificateStatus.INACTIVE);
            assertTrue("An Exception has not been thrown", false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue(true);
        } catch (final Exception e) {
            assertTrue("CredentialManagerEntityNotFoundException was expected", false);
        }

    }

    @Test
    public void compareCrlsAndRetrieveTest() throws CRLEncodingException, CredentialManagerInvalidArgumentException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException,
            CredentialManagerCRLServiceException, CredentialManagerCRLEncodingException, CredentialManagerServiceException {

        final SortedSet<CredentialManagerCRLIdentifier> currentClrIdentifiers = new TreeSet<CredentialManagerCRLIdentifier>();
        final X509CRL crl1 = generateCrl(1);
        final CredentialManagerCRLIdentifier crlId1 = new CredentialManagerCRLIdentifier(crl1);
        currentClrIdentifiers.add(crlId1);
        final X509CRL crl2 = generateCrl(2);
        final CredentialManagerCRLIdentifier crlId2 = new CredentialManagerCRLIdentifier(crl2);
        currentClrIdentifiers.add(crlId2);

        CredentialManagerCrlMaps cmCrlMaps = null;
        // returns new empty crlMaps
        cmCrlMaps = credMServiceBean.compareCrlsAndRetrieve("profileName", false, currentClrIdentifiers, true, true);
        assertTrue(cmCrlMaps.getInternalCACrlMap().isEmpty() && cmCrlMaps.getExternalCACrlMap().isEmpty());

        // null crl ids input
        cmCrlMaps = null;
        try {
            cmCrlMaps = credMServiceBean.compareCrlsAndRetrieve("profileName", false, null, true, true);
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(cmCrlMaps == null);
        }

        // return list and retrieve the same crls(valid currentIdentifiers)
        final CredentialManagerCALists caList = new CredentialManagerCALists();
        final CredentialManagerTrustCA trustCA1 = new CredentialManagerTrustCA("pippo", false);
        final CredentialManagerTrustCA trustCA2 = new CredentialManagerTrustCA("pippoExt", false);
        caList.getInternalCAList().add(trustCA1);
        caList.getExternalCAList().add(trustCA2);
        when(profileManager.getTrustCAList("profileName")).thenReturn(caList);
        final Map<String, CredentialManagerX509CRL> MapCrl1 = new HashMap<String, CredentialManagerX509CRL>();
        final Map<String, CredentialManagerX509CRL> MapCrl2 = new HashMap<String, CredentialManagerX509CRL>();
        MapCrl1.put(trustCA1.getTrustCAName(), new CredentialManagerX509CRL(crl1));
        MapCrl2.put(trustCA2.getTrustCAName(), new CredentialManagerX509CRL(crl2));
        when(certificateManager.getCrl(trustCA1.getTrustCAName(), trustCA1.isChainRequired(), false)).thenReturn(MapCrl1);
        when(certificateManager.getCrl(trustCA2.getTrustCAName(), trustCA2.isChainRequired(), true)).thenReturn(MapCrl2);

        cmCrlMaps = credMServiceBean.compareCrlsAndRetrieve("profileName", false, currentClrIdentifiers, true, true);
        assertTrue(cmCrlMaps == null);

        // both flag false
        cmCrlMaps = credMServiceBean.compareCrlsAndRetrieve("profileName", false, currentClrIdentifiers, false, false);
        assertTrue(cmCrlMaps.getExternalCACrlMap().size() == 1 && cmCrlMaps.getInternalCACrlMap().size() == 1);

        when(profileManager.getTrustCAListFromTP("profileName", null)).thenReturn(caList);
        cmCrlMaps = credMServiceBean.compareCrlsAndRetrieveTP("profileName", true, currentClrIdentifiers, true, false);
        assertTrue(cmCrlMaps.getExternalCACrlMap().size() == 1 && cmCrlMaps.getInternalCACrlMap().size() == 1);

        final CredentialManagerCrlMaps cmGetCrl = credMServiceBean.getCRLs("profileName", false);
        final CredentialManagerCrlMaps cmGetCrlTP = credMServiceBean.getCRLsTP("profileName", false);
        assertTrue(cmGetCrlTP.getExternalCACrlMap().values().containsAll(cmGetCrl.getExternalCACrlMap().values())
                && cmGetCrlTP.getInternalCACrlMap().values().containsAll(cmGetCrl.getInternalCACrlMap().values()));
        assertTrue(cmGetCrlTP.getExternalCACrlMap().values().containsAll(cmCrlMaps.getExternalCACrlMap().values())
                && cmGetCrlTP.getInternalCACrlMap().values().containsAll(cmCrlMaps.getInternalCACrlMap().values()));

        // exceptions Note that at this level the passed chainRequired changes nothing
        cmCrlMaps = null;
        when(certificateManager.getCrl(trustCA1.getTrustCAName(), trustCA1.isChainRequired(), false))
                .thenThrow(new CredentialManagerCRLServiceException());
        try {
            cmCrlMaps = credMServiceBean.compareCrlsAndRetrieveTP("profileName", true, currentClrIdentifiers, true, false);
            assertTrue(false);
        } catch (final CredentialManagerCRLServiceException e) {
            assertTrue(cmCrlMaps == null);
        }
        caList.getInternalCAList().clear();
        when(certificateManager.getCrl(trustCA2.getTrustCAName(), trustCA2.isChainRequired(), true))
                .thenThrow(new CredentialManagerCertificateServiceException());
        try {
            cmCrlMaps = credMServiceBean.compareCrlsAndRetrieveTP("profileName", true, currentClrIdentifiers, false, true);
            assertTrue(false);
        } catch (final CredentialManagerCRLServiceException e) {
            assertTrue(cmCrlMaps == null);
        }
    }

    @Test
    public void testRevokeExceptions() throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException,
            CredentialManagerCertificateServiceException, CredentialManagerCertificateNotFoundException, CredentialManagerExpiredCertificateException,
            CredentialManagerAlreadyRevokedCertificateException {

        Mockito.doThrow(CredentialManagerEntityNotFoundException.class).when(certificateManager).RevokeCertificateByEntity(
                Matchers.eq("entityExc1"), Matchers.eq(CredentialManagerRevocationReason.SUPERSEDED), Matchers.any(Date.class));
        try {
            credMServiceBean.revokeCertificateByEntity("entityExc1", CredentialManagerRevocationReason.SUPERSEDED, new Date());
            assertTrue(false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue(true);
        }
        Mockito.doThrow(CredentialManagerInternalServiceException.class).when(certificateManager).RevokeCertificateByEntity(
                Matchers.eq("entityExc2"), Matchers.eq(CredentialManagerRevocationReason.SUPERSEDED), Matchers.any(Date.class));
        try {
            credMServiceBean.revokeCertificateByEntity("entityExc2", CredentialManagerRevocationReason.SUPERSEDED, new Date());
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }

        Mockito.doThrow(CredentialManagerCertificateServiceException.class).when(certificateManager).RevokeCertificateById(
                Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.SUPERSEDED),
                Matchers.any(Date.class));
        try {
            credMServiceBean.revokeCertificateById(new CredentialManagerCertificateIdentifier(), CredentialManagerRevocationReason.SUPERSEDED,
                    new Date());
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        Mockito.doThrow(CredentialManagerCertificateNotFoundException.class).when(certificateManager).RevokeCertificateById(
                Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.AA_COMPROMISE),
                Matchers.any(Date.class));
        try {
            credMServiceBean.revokeCertificateById(new CredentialManagerCertificateIdentifier(), CredentialManagerRevocationReason.AA_COMPROMISE,
                    new Date());
            assertTrue(false);
        } catch (final CredentialManagerCertificateNotFoundException e) {
            assertTrue(true);
        }
        Mockito.doThrow(CredentialManagerExpiredCertificateException.class).when(certificateManager).RevokeCertificateById(
                Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.AFFILIATION_CHANGED),
                Matchers.any(Date.class));
        try {
            credMServiceBean.revokeCertificateById(new CredentialManagerCertificateIdentifier(),
                    CredentialManagerRevocationReason.AFFILIATION_CHANGED, new Date());
            assertTrue(false);
        } catch (final CredentialManagerExpiredCertificateException e) {
            assertTrue(true);
        }
        Mockito.doThrow(CredentialManagerAlreadyRevokedCertificateException.class).when(certificateManager).RevokeCertificateById(
                Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.CA_COMPROMISE),
                Matchers.any(Date.class));
        try {
            credMServiceBean.revokeCertificateById(new CredentialManagerCertificateIdentifier(), CredentialManagerRevocationReason.CA_COMPROMISE,
                    new Date());
            assertTrue(false);
        } catch (final CredentialManagerAlreadyRevokedCertificateException e) {
            assertTrue(true);
        }

    }

    private PKCS10CertificationRequest createCSR(final KeyPair keyPair) throws CredentialManagerServiceException {
        PKCS10CertificationRequest csr = null;
        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        final Subject subject = new Subject();
        final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();
        subjectMap.put(SubjectFieldType.COMMON_NAME, "mara");

        for (final Entry<SubjectFieldType, String> entry : subjectMap.entrySet()) {
            final SubjectField subFieldTemp = new SubjectField();
            subFieldTemp.setType(entry.getKey());
            subFieldTemp.setValue(entry.getValue());
            subject.getSubjectFields().add(subFieldTemp);
        }

        entityInfo.setSubject(subject);
        entityInfo.setName("mara");
        entity.setEntityInfo(entityInfo);

        final String signatureAlgorithm = "SHA256withRSA";

        final Attribute[] att = new Attribute[0];

        csr = getCSR(entity, signatureAlgorithm, keyPair, att);

        return csr;
    }

    private PKCS10CertificationRequest createCSRForCA(final KeyPair keyPair) throws CredentialManagerServiceException {
        PKCS10CertificationRequest csr = null;
        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        final Subject subject = new Subject();
        final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();
        subjectMap.put(SubjectFieldType.COMMON_NAME, "ENMManagementCA");

        for (final Entry<SubjectFieldType, String> entry : subjectMap.entrySet()) {
            final SubjectField subFieldTemp = new SubjectField();
            subFieldTemp.setType(entry.getKey());
            subFieldTemp.setValue(entry.getValue());
            subject.getSubjectFields().add(subFieldTemp);
        }

        entityInfo.setSubject(subject);
        entityInfo.setName("ENMManagementCA");
        entity.setEntityInfo(entityInfo);
        final String signatureAlgorithm = "SHA256withRSA";

        final Attribute[] att = new Attribute[0];

        csr = getCSR(entity, signatureAlgorithm, keyPair, att);

        return csr;
    }

    private PKCS10CertificationRequest getCSR(final Entity eentity, final String signatureAlgorithm, final KeyPair keyPair,
            final Attribute[] attributes)
            throws CredentialManagerServiceException {

        try {
            final PKCS10CertificationRequest csr = CertificateUtils.generatePKCS10Request(signatureAlgorithm, eentity, keyPair, attributes, null);

            return csr;

        } catch (final Exception e) {

            throw new CredentialManagerCertificateServiceException();
        }
    }

    private static CredentialManagerCertificateAuthority getCredMCAs(final String filename, final String chainName) {
        final CredentialManagerCertificateAuthority ret = new CredentialManagerCertificateAuthority(chainName);

        final JKSReader reader = new JKSReader(readFromClasspath(filename), "secret", "JKS");
        final List<Certificate> certs = reader.getAllCertificates();
        for (final Certificate cert : certs) {
            X509CertificateHolder x509CertHolder;
            try {
                x509CertHolder = new X509CertificateHolder(cert.getEncoded());
                ret.add(new JcaX509CertificateConverter().getCertificate(x509CertHolder));
            } catch (CertificateException | IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return ret;
    }

    private static InputStream readFromClasspath(final String filename) {
        InputStream input;
        input = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        return input;
    }

    private X509CRL generateCrl(final int crlNumber) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            final Date thisUpdate = new Date(System.currentTimeMillis());
            final Date nextUpdate = new Date(System.currentTimeMillis() + 10 * 24L * 60L * 60L * 1000L);
            final X500Name issuerName = new X500Name("CN=pippo");
            final X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuerName, thisUpdate);
            final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);
            crlGen.setNextUpdate(nextUpdate);
            crlGen.addCRLEntry(BigInteger.ONE, thisUpdate, CRLReason.PRIVILEGE_WITHDRAWN);
            if (crlNumber != 0) {
                crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(crlNumber)));
            }
            final ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION").setProvider("BC").build(keyPair.getPrivate());
            final X509CRLHolder crlHolder = crlGen.build(sigGen);
            final CredentialManagerX509CRL crl = new CredentialManagerX509CRL(crlHolder.getEncoded());
            return crl.retrieveCRL();
        } catch (final Exception e) {
            assertTrue("generateCrl failed!", false);
        }
        return null;
    }
}
