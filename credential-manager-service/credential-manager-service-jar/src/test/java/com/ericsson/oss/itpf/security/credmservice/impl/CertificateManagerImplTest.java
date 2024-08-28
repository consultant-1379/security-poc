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
package com.ericsson.oss.itpf.security.credmservice.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerAlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateExsitsException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerErrorCodes;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidCSRException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.InvalidInvalidityDateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerCertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RootCertificateRevocationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.services.security.pkimock.api.MockCACertificateManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockCACrlManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockEntityCertificateManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockEntityManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockExtCACRLManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockExtCACertificateManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockRevocationService;
import com.ericsson.oss.services.security.pkimock.impl.PKICACertificateManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKICACrlManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIConfigurationManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIEntityCertificateManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIEntityManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIExtCACRLManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIExtCACertificateManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.PKIProfileManagementServiceImpl;
import com.ericsson.oss.services.security.pkimock.impl.RevocationServiceImpl;
import com.ericsson.oss.services.security.pkimock.util.CertificateUtils;

//@PowerMockIgnore("javax.security.auth.x500.*")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(MockitoJUnitRunner.class)
//@RunWith(PowerMockRunner.class)
public class CertificateManagerImplTest {

    @Mock
    SystemRecorderWrapper systemRecorder;

    @Mock
    MockEntityManagementService mockEntityManager;

    MockCACertificateManagementService pkiCACertificateManager;

    MockExtCACertificateManagementService pkiExtCACertificateManager;

    MockEntityCertificateManagementService pkiEntityCertificateManager;

    PKIProfileManagementServiceImpl pkiProfileManager;

    PKIEntityManagementServiceImpl pkiEntityManager;

    PKIConfigurationManagementServiceImpl pkiConfigurationManager;

    MockCACrlManagementService pkiIntCACrlManager;

    MockExtCACRLManagementService pkiExtCACrlManager;

    MockRevocationService revokeManager;

    @InjectMocks
    CertificateManagerImpl certificateManager = new CertificateManagerImpl();

    //  CertificateManagerImpl certificateManagerClass = new CertificateManagerImpl();

    @Before
    public void setup() {
        this.pkiCACertificateManager = new PKICACertificateManagementServiceImpl();
        this.pkiExtCACertificateManager = new PKIExtCACertificateManagementServiceImpl();
        this.pkiEntityCertificateManager = new PKIEntityCertificateManagementServiceImpl();
        this.pkiProfileManager = new PKIProfileManagementServiceImpl();
        this.pkiEntityManager = new PKIEntityManagementServiceImpl();
        this.pkiIntCACrlManager = new PKICACrlManagementServiceImpl();
        this.pkiExtCACrlManager = new PKIExtCACRLManagementServiceImpl();
        this.revokeManager = new RevocationServiceImpl();
        this.pkiConfigurationManager = new PKIConfigurationManagementServiceImpl();
        this.pkiEntityManager.initEndEntityCollection();
        this.pkiEntityManager.initCAEntityCollection();
        this.pkiProfileManager.initProfileCollection();
        this.pkiConfigurationManager.initCategoriesCollection();

        try {
            final Field pkiCACertificateManagerField = CertificateManagerImpl.class.getDeclaredField("mockCACertificateManager");
            final Field pkiExtCACertificateManagerField = CertificateManagerImpl.class.getDeclaredField("mockExtCACertificateManager");
            pkiCACertificateManagerField.setAccessible(true);
            pkiExtCACertificateManagerField.setAccessible(true);
            pkiCACertificateManagerField.set(this.certificateManager, this.pkiCACertificateManager);
            pkiExtCACertificateManagerField.set(this.certificateManager, this.pkiExtCACertificateManager);

            final Field pkiEntityCertificateManagerField = CertificateManagerImpl.class.getDeclaredField("mockEntityCertificateManager");
            pkiEntityCertificateManagerField.setAccessible(true);
            pkiEntityCertificateManagerField.set(this.certificateManager, this.pkiEntityCertificateManager);

            final Field pkiIntCACrlManagerField = CertificateManagerImpl.class.getDeclaredField("mockIntCACrlManager");
            final Field pkiExtCACrlManagerField = CertificateManagerImpl.class.getDeclaredField("mockExtCACRLManager");
            pkiIntCACrlManagerField.setAccessible(true);
            pkiExtCACrlManagerField.setAccessible(true);
            pkiIntCACrlManagerField.set(this.certificateManager, this.pkiIntCACrlManager);
            pkiExtCACrlManagerField.set(this.certificateManager, this.pkiExtCACrlManager);

            final Field revocationManagerField = CertificateManagerImpl.class.getDeclaredField("mockRevokeManager");
            revocationManagerField.setAccessible(true);
            revocationManagerField.set(this.certificateManager, this.revokeManager);
            final Field pkiProfileManagerField = PKIEntityCertificateManagementServiceImpl.class.getDeclaredField("profileManagement");
            pkiProfileManagerField.setAccessible(true);
            pkiProfileManagerField.set(this.pkiEntityCertificateManager, this.pkiProfileManager);
            final Field pkiEntityManagerField = PKIEntityCertificateManagementServiceImpl.class.getDeclaredField("entityManagement");
            pkiEntityManagerField.setAccessible(true);
            pkiEntityManagerField.set(this.pkiEntityCertificateManager, this.pkiEntityManager);
            final Field pkiProfile_2ManagerField = PKIEntityManagementServiceImpl.class.getDeclaredField("profileManagement");
            pkiProfile_2ManagerField.setAccessible(true);
            pkiProfile_2ManagerField.set(this.pkiEntityManager, this.pkiProfileManager);
            final Field pkiConfigurationManagerField = PKIEntityManagementServiceImpl.class.getDeclaredField("configurationManagement");
            pkiConfigurationManagerField.setAccessible(true);
            pkiConfigurationManagerField.set(this.pkiEntityManager, this.pkiConfigurationManager);
            final Field pkiEntity_2ManagerField = RevocationServiceImpl.class.getDeclaredField("entityManagement");
            pkiEntity_2ManagerField.setAccessible(true);
            pkiEntity_2ManagerField.set(this.revokeManager, this.pkiEntityManager);

            final Field entityManager = CertificateManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager.setAccessible(true);
            entityManager.set(this.certificateManager, this.pkiEntityManager);

        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Test
    public void testGetCSR() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {

        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);

        final String cN = "mara";
        final PKCS10CertificationRequest csr = this.createCSR(keyPair, "SHA256withRSA", cN);

        assertNotNull(csr);

        assertEquals(new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA").getAlgorithm(),
                csr.getSignatureAlgorithm().getAlgorithm());
        final org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();

        for (final org.bouncycastle.asn1.pkcs.Attribute attr : attributes) {
            assertEquals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, attr.getAttrType());

            final Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
            final Enumeration e = extensions.oids();
            while (e.hasMoreElements()) {
                final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
                final Extension ext = extensions.getExtension(oid);
                assertEquals(Extension.subjectAlternativeName, ext.getExtnId());
                final GeneralNames gns = GeneralNames.fromExtensions(extensions, oid);
                assertNotNull(gns);
                assertEquals("localhost", gns.getNames()[0].getName().toString());

            }
        }

        try {
            // Reencode SubjectPublicKeyInfo, let java decode it.
            final byte[] encodedKey = encode(csr.getSubjectPublicKeyInfo());

            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);

            final KeyFactory fact = KeyFactory.getInstance("RSA");
            final PublicKey csrPubKey = fact.generatePublic(keySpec);
            assertEquals(keyPair.getPublic(), csrPubKey);
        } catch (final InvalidKeySpecException | CertificateEncodingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        final RDN cn = csr.getSubject().getRDNs(BCStyle.CN)[0];
        final String csrCN = IETFUtils.valueToString(cn.getFirst().getValue());
        assertEquals(cN, csrCN);

    }

    @Test
    public void testGetCertificate() throws CertificateEncodingException, CredentialManagerServiceException, InvalidSubjectException,
            MissingMandatoryFieldException, AlgorithmNotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException,
            EntityAlreadyExistsException, EntityServiceException, InvalidEntityAttributeException, InvalidProfileException, ProfileNotFoundException,
            CertificateExtensionException, UnSupportedCertificateVersion, CANotFoundException, InvalidCAException, InvalidProfileAttributeException,
            ProfileAlreadyExistsException, ProfileServiceException, ProfileInUseException {
        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);

        final PKCS10CertificationRequest csr = this.createCSR(keyPair, "SHA256withRSA", "mara");
        CredentialManagerPKCS10CertRequest csrHolder;
        this.createProfilesOnPKI(true);
        this.createEntityOnPKI("entityName");
        try {
            csrHolder = new CredentialManagerPKCS10CertRequest(csr);

            final CredentialManagerX509Certificate[] cert = this.certificateManager.getCertificate(csrHolder, "entityName", false, null);

            //assertEquals("CN=ENMManagementCA,OU=EricssonOAM,O=Ericsson", cert.retrieveCertificate().getIssuerDN().getName());

            final X509Certificate x509Certificate = cert[0].retrieveCertificate();
            //            final X509Certificate jcaX509Certificate = new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(x509Certificate
            //                    .getEncoded()));
            final String check = x509Certificate.getPublicKey().getAlgorithm();
            assertEquals("RSA", check);
            assertEquals("CN=mara", x509Certificate.getSubjectX500Principal().getName());
            assertEquals("SHA256WITHRSA", x509Certificate.getSigAlgName());
            assertTrue(!x509Certificate.getSubjectAlternativeNames().isEmpty());
            assertEquals(1, x509Certificate.getSubjectAlternativeNames().size());
            for (final List<?> element : x509Certificate.getSubjectAlternativeNames()) {
                assertEquals(2, element.get(0));
                assertEquals("localhost", element.get(1));
            }

            //assertEquals("CN=ENMManagementCA,OU=EricssonOAM,O=Ericsson", x509Certificate.getIssuerX500Principal());
        } catch (final IOException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            this.deleteProfilesOnPKI(true);
        }
    }

    @Test
    public void testGetCertificateExceptions()
            throws CertificateExtensionException, InvalidSubjectException, MissingMandatoryFieldException, UnSupportedCertificateVersion,
            AlgorithmNotFoundException, CANotFoundException, EntityCategoryNotFoundException, InvalidCAException, InvalidEntityCategoryException,
            InvalidProfileAttributeException, ProfileAlreadyExistsException, ProfileNotFoundException, ProfileServiceException, ProfileInUseException,
            CredentialManagerCertificateEncodingException, CredentialManagerCertificateGenerationException, CredentialManagerInvalidCSRException,
            CredentialManagerInvalidEntityException, CredentialManagerCertificateExsitsException {
        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);

        final String cN = "mara";
        final PKCS10CertificationRequest csr = this.createCSR(keyPair, "SHA256withRSA", cN);
        CredentialManagerPKCS10CertRequest csrHolder = null;
        this.createProfilesOnPKI(true);
        try {
            csrHolder = new CredentialManagerPKCS10CertRequest(csr);
        } catch (final IOException e1) {
            e1.printStackTrace();
        }
        try {
            this.certificateManager.getCertificate(csrHolder, "entityName12", false, null);
            assertTrue("EntityNotFoundException should have been thrown", false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue(true);
        } finally {
            this.deleteProfilesOnPKI(true);
        }
    }

    @Test
    public void testGetCertificateExceptions2() throws OTPExpiredException, InvalidOTPException, AlgorithmNotFoundException,
            CertificateGenerationException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException,
            RevokedCertificateException, EntityNotFoundException, InvalidEntityException, InvalidEntityAttributeException,
            CredentialManagerCertificateEncodingException, CertificateServiceException, CredentialManagerCertificateExsitsException {

        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);
        final PKCS10CertificationRequest csr = this.createCSR(keyPair, "SHA256withRSA", "pippo");
        CredentialManagerPKCS10CertRequest csrHolder = null;
        try {
            csrHolder = new CredentialManagerPKCS10CertRequest(csr);
        } catch (final IOException e1) {
            assertTrue(false);
        }
        final PKIEntityCertificateManagementServiceImpl pkiEntityCertManager = Mockito.mock(PKIEntityCertificateManagementServiceImpl.class);

        try {
            final Field pkiEntCertManagerField2 = CertificateManagerImpl.class.getDeclaredField("mockEntityCertificateManager");
            pkiEntCertManagerField2.setAccessible(true);
            pkiEntCertManagerField2.set(this.certificateManager, pkiEntityCertManager);
        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        Mockito.when(pkiEntityCertManager.generateCertificate("EntityException", PKIModelMapper.pkiCSRFrom(csrHolder), "otp"))
                .thenThrow(new CertificateGenerationException()).thenThrow(new InvalidCertificateRequestException())
                .thenThrow(new InvalidEntityException()).thenThrow(new InvalidCAException()).thenThrow(new CertificateServiceException())
                .thenThrow(new AlgorithmNotFoundException()).thenThrow(new ExpiredCertificateException()).thenThrow(new RevokedCertificateException())
                .thenThrow(new EntityNotFoundException()).thenThrow(new InvalidEntityAttributeException())
                .thenThrow(new CredentialManagerCertificateEncodingException()).thenThrow(new OTPExpiredException())
                .thenThrow(new InvalidOTPException()).thenThrow(new InvalidCertificateStatusException());

        for (int i = 0; i < 14; i++) {
            try {
                final CredentialManagerX509Certificate[] cert = this.certificateManager.getCertificate(csrHolder, "EntityException", false, "otp");
                assertTrue(false);
            } catch (final CredentialManagerCertificateGenerationException e) {
                assertTrue(i == 0 || i == 5 || i == 6 || i == 7 || i == 4);
            } catch (final CredentialManagerInvalidCSRException e) {
                assertTrue(i == 1);
            } catch (final CredentialManagerInvalidEntityException e) {
                assertTrue(i == 2 || i == 3 || i == 9 || i == 11 || i == 12 || i == 13);
            } catch (final CredentialManagerEntityNotFoundException e) {
                assertTrue(i == 8);
            } catch (final CredentialManagerCertificateEncodingException e) {
                assertTrue(i == 10);
            }

        }
    }

    @Test
    public void testGetCertificateChain() throws CertificateEncodingException, CredentialManagerServiceException, InvalidSubjectException,
            MissingMandatoryFieldException, AlgorithmNotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException,
            EntityAlreadyExistsException, EntityServiceException, InvalidEntityAttributeException, InvalidProfileException, ProfileNotFoundException,
            CertificateExtensionException, UnSupportedCertificateVersion, CANotFoundException, InvalidCAException, InvalidProfileAttributeException,
            ProfileAlreadyExistsException, ProfileServiceException, ProfileInUseException {
        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);

        final String cN = "dummy";
        final PKCS10CertificationRequest csr = this.createCSR(keyPair, "SHA256withRSA", cN);
        CredentialManagerPKCS10CertRequest csrHolder;
        this.createProfilesOnPKI(true);
        this.createEntityOnPKI("entityNameChain");

        try {
            csrHolder = new CredentialManagerPKCS10CertRequest(csr);

            final CredentialManagerX509Certificate[] cert = this.certificateManager.getCertificate(csrHolder, "entityName", true, null);

            // Note: Mock PKI return a dummy chain of length 3 without the required starting certificate for the entity itself....
            assertEquals(3, cert.length);

            for (int i = 0; i < cert.length; i++) {
                final X509Certificate x509Certificate = cert[i].retrieveCertificate();

                assertEquals("RSA", x509Certificate.getPublicKey().getAlgorithm());
                if (i == 0) {
                    assertEquals("CN=ENMManagementCA,OU=EricssonOAM,O=Ericsson", x509Certificate.getSubjectX500Principal().getName());
                } else if (i == 1) {
                    assertEquals("CN=ENMInfrastructureCA,OU=EricssonOAM,O=Ericsson", x509Certificate.getSubjectX500Principal().getName());
                } else if (i == 2) {
                    assertEquals("CN=ENMPKIRootCA,OU=EricssonOAM,O=Ericsson", x509Certificate.getSubjectX500Principal().getName());
                }

                assertEquals("SHA256WITHRSA", x509Certificate.getSigAlgName());
            }
        } catch (final IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            this.deleteProfilesOnPKI(true);
        }
    }

    @Test
    public void testExceptions() {

        final CredentialManagerInternalServiceException internalServiceException = new CredentialManagerInternalServiceException("message");
        assertEquals(CredentialManagerErrorCodes.UNEXPECTED_INTERNAL_ERROR + " : " + "message", internalServiceException.getMessage());

        final CredentialManagerInvalidEntityException invalidEntityException = new CredentialManagerInvalidEntityException("message");
        assertEquals(CredentialManagerErrorCodes.ENTITY_INVALID + " : " + "message", invalidEntityException.getMessage());

        final CredentialManagerEntityNotFoundException entityNotFoundException = new CredentialManagerEntityNotFoundException("message");
        assertEquals(CredentialManagerErrorCodes.ENTITY_NOT_FOUND + " : " + "message", entityNotFoundException.getMessage());

        final CredentialManagerInvalidArgumentException invalidArgumentException = new CredentialManagerInvalidArgumentException("message");
        assertEquals(CredentialManagerErrorCodes.INVALID_ARGUMENT + " : " + "message", invalidArgumentException.getMessage());

        final CredentialManagerInvalidProfileException invalidProfileException = new CredentialManagerInvalidProfileException("message");
        assertEquals(CredentialManagerErrorCodes.PROFILE_INVALID + " : " + "message", invalidProfileException.getMessage());

        final CredentialManagerProfileNotFoundException profileNotFoundException = new CredentialManagerProfileNotFoundException("message");
        assertEquals(CredentialManagerErrorCodes.PROFILE_NOT_FOUND + " : " + "message", profileNotFoundException.getMessage());

        final CredentialManagerCertificateEncodingException certificateEncodingException = new CredentialManagerCertificateEncodingException(
                "message");
        assertEquals(CredentialManagerErrorCodes.CERTIFICATE_ENCODING_ERROR + " : " + "message", certificateEncodingException.getMessage());

        final CredentialManagerCertificateServiceException certificateServiceException = new CredentialManagerCertificateServiceException("message");
        assertEquals(CredentialManagerErrorCodes.CERTIFICATE_SERVICE_ERROR + " : " + "message", certificateServiceException.getMessage());
    }

    @Test
    public void testGetTrust() throws CertificateEncodingException, CredentialManagerServiceException {

        final CredentialManagerCertificateAuthority ca = this.certificateManager
                .getTrustCertificates(new CredentialManagerTrustCA("CN=ENMManagementCA", false), false);

        assertNotNull(ca);
        assertEquals(3, ca.getCACertificateChain().size());

        X509CertificateHolder certificateHolder;
        try {
            certificateHolder = new X509CertificateHolder(ca.getCACertificateChain().get(0).getCertBytes());
            final X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);

            final X509Certificate ca0 = new JcaX509CertificateConverter()
                    .getCertificate(new X509CertificateHolder(ca.getCACertificateChain().get(0).retrieveCertificate().getEncoded()));
            final X509Certificate ca1 = new JcaX509CertificateConverter()
                    .getCertificate(new X509CertificateHolder(ca.getCACertificateChain().get(1).retrieveCertificate().getEncoded()));
            final X509Certificate ca2 = new JcaX509CertificateConverter()
                    .getCertificate(new X509CertificateHolder(ca.getCACertificateChain().get(2).retrieveCertificate().getEncoded()));

            assertEquals("CN=ENMManagementCA, OU=EricssonOAM, O=Ericsson", certificate.getSubjectDN().getName());
            assertEquals("CN=ENMInfrastructureCA, OU=EricssonOAM, O=Ericsson", ca0.getIssuerDN().getName());
            assertEquals("CN=ENMInfrastructureCA, OU=EricssonOAM, O=Ericsson", ca1.getSubjectDN().getName());
            assertEquals("CN=ENMPKIRootCA, OU=EricssonOAM, O=Ericsson", ca1.getIssuerDN().getName());
            assertEquals("CN=ENMPKIRootCA, OU=EricssonOAM, O=Ericsson", ca2.getSubjectDN().getName());
            assertEquals("CN=ENMPKIRootCA, OU=EricssonOAM, O=Ericsson", ca2.getIssuerDN().getName());
        } catch (IOException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @Test
    public void testGetTrustChain() throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException,
            CertificateServiceException, InvalidCAException, CertificateNotFoundException, EntityNotFoundException, InvalidEntityAttributeException,
            InvalidCertificateStatusException, InvalidEntityException, CredentialManagerInvalidArgumentException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException,
            CredentialManagerInternalServiceException {

        CredentialManagerCertificateAuthority ca = this.certificateManager.getTrustCertificates(new CredentialManagerTrustCA(null, false), false);

        assertNotNull(ca);
        assertEquals(0, ca.getCACertificateChain().size());
        //this variable will be used later, but I have to set it here because mockCACertManager will be overwritten below
        final List<Certificate> certList = this.certificateManager.mockCACertificateManager.listCertificates("CN=ENMManagementCA",
                CertificateStatus.ACTIVE);

        final PKICACertificateManagementServiceImpl pkiCACertManager2 = Mockito.mock(PKICACertificateManagementServiceImpl.class);
        final Field pkiIntCACertManagerField2 = CertificateManagerImpl.class.getDeclaredField("mockCACertificateManager");
        pkiIntCACertManagerField2.setAccessible(true);
        pkiIntCACertManagerField2.set(this.certificateManager, pkiCACertManager2);

        final CredentialManagerTrustCA cmTrust = new CredentialManagerTrustCA("ENMManagementCA", true);
        Mockito.when(pkiCACertManager2.getCertificateChainList(cmTrust.getTrustCAName(), CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(new ArrayList<CertificateChain>());

        ca = this.certificateManager.getTrustCertificates(cmTrust, false);

        assertNotNull(ca);
        assertEquals(0, ca.getCACertificateChain().size());

        //To be found same certs using same CMCertAuthority object
        final CertificateChain chain = new CertificateChain();
        chain.setCertificateChain(certList);
        final CertificateChain chain2 = new CertificateChain();
        chain2.setCertificateChain(certList);
        final List<CertificateChain> chainList = new ArrayList<CertificateChain>();
        chainList.add(chain);
        chainList.add(chain2);

        Mockito.when(pkiCACertManager2.getCertificateChainList(cmTrust.getTrustCAName(), CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(chainList);

        ca = this.certificateManager.getTrustCertificates(cmTrust, false);
        assertTrue(ca.getSimpleName().equals(cmTrust.getTrustCAName()) && ca.getCACertificateChain().size() == 3);

        //getTrustCertificates exceptions
        cmTrust.setTrustCAName("ENMExceptionsCA");

        Mockito.when(pkiCACertManager2.getCertificateChainList(cmTrust.getTrustCAName(), CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new InvalidCAException()).thenThrow(new CredentialManagerCertificateEncodingException())
                .thenThrow(new CertificateServiceException()).thenThrow(new EntityNotFoundException())
                .thenThrow(new InvalidEntityAttributeException()).thenThrow(new InvalidCertificateStatusException())
                .thenThrow(new InvalidEntityException());
        for (int i = 0; i < 7; i++) {
            try {
                ca = this.certificateManager.getTrustCertificates(cmTrust, false);
                assertTrue(false);
            } catch (final CredentialManagerInvalidArgumentException e) {
                assertTrue(i == 0 || (i > 2 && i < 7));
            } catch (final CredentialManagerCertificateEncodingException e) {
                assertTrue(i == 1);
            } catch (final CredentialManagerInternalServiceException e) {
                assertTrue(i == 2);
            }
        }
    }

    @Test
    public void testGetCRLsOfEPPKI() throws CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLEncodingException, MissingMandatoryFieldException, ExternalCRLNotFoundException, ExternalCANotFoundException,
            ExternalCRLEncodedException, ExternalCredentialMgmtServiceException {
        final Map<String, CredentialManagerX509CRL> crls = this.certificateManager.getCrl("VC_Root_CA_A1", true, true);
        assertEquals(1, crls.size());
        //MockPKI file ca_oss_enm_map.properties DEFAULT property Management is added at the end of the name
        //and it is set as crl issuer. That's because ca_oss_enm_map does not contain a VC_Root_CA_A1 entry
        final X509CRL crl = crls.get("VC_Root_CA_A1_ENMManagementCA").retrieveCRL();
        assertTrue(crl.getIssuerDN().getName().contains("ENMManagementCA"));

        final PKIExtCACRLManagementServiceImpl pkiExtCACrlManager2 = Mockito.mock(PKIExtCACRLManagementServiceImpl.class);
        Field pkiExtCACrlManagerField2;
        try {
            pkiExtCACrlManagerField2 = CertificateManagerImpl.class.getDeclaredField("mockExtCACRLManager");
            pkiExtCACrlManagerField2.setAccessible(true);
            pkiExtCACrlManagerField2.set(this.certificateManager, pkiExtCACrlManager2);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            assertTrue(false);
        }
        Mockito.when(pkiExtCACrlManager2.listExternalCRLInfo("excCRLCA")).thenThrow(new ExternalCRLNotFoundException())
                .thenThrow(new UnsupportedOperationException()).thenThrow(new ClassCastException()).thenThrow(new MissingMandatoryFieldException())
                .thenThrow(new NullPointerException()).thenThrow(new IllegalArgumentException()).thenThrow(new ExternalCANotFoundException())
                .thenThrow(new ExternalCredentialMgmtServiceException()).thenThrow(new ExternalCRLEncodedException());

        Map<String, CredentialManagerX509CRL> crls2 = null;
        for (int i = 0; i < 9; i++) {
            try {
                crls2 = this.certificateManager.getCrl("excCRLCA", false, true);
                if (i == 0) {
                    assertTrue(crls2 != null);
                }
            } catch (final CredentialManagerCRLServiceException e) {
                if (i != 0) {
                    assertTrue(true);
                } else {
                    assertTrue(false);
                }
            }
        }
    }

    @Test
    public void testGetCrlNormalCase()
            throws CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException, CredentialManagerCRLEncodingException {

        final Map<String, CredentialManagerX509CRL> testCrl = this.certificateManager.getCrl("CN=ENMManagementCA", false, false);
        assertNotNull(testCrl);
        assertEquals(1, testCrl.size());

    }

    @Test
    public void testBadParametersGetCrl()
            throws CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException, CredentialManagerCRLEncodingException {

        try {
            this.certificateManager.getCrl(null, false, false);
            assertTrue("Expected exception because of null CAname", false);
        } catch (final CredentialManagerCRLServiceException e) {
            assertTrue(true);
        }
        this.certificateManager.mockExtCACRLManager = null;
        try {
            this.certificateManager.getCrl("CN=EPPKI_CA", true, true);
            assertTrue("Expected exception because of externalCrlManager null", false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }
        this.certificateManager.mockIntCACrlManager = null;

        try {
            this.certificateManager.getCrl("CN=ENMManagementCA", false, false);
            assertTrue("Expected exception because of null mockIntCACrlManager", false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }

        try {
            this.certificateManager.getCrl("CN=ENMManagementCA", false, true);
            assertTrue("Expected exception because of null mockExtCACRLManager", false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testBadEntityGetCrl()
            throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {

        final PKIEntityManagementServiceImpl pkiEntityManager2 = Mockito.mock(PKIEntityManagementServiceImpl.class);

        Field entityManager2 = null;
        try {
            entityManager2 = CertificateManagerImpl.class.getDeclaredField("mockEntityManager");
            entityManager2.setAccessible(true);
            entityManager2.set(this.certificateManager, pkiEntityManager2);

        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        final CAEntity c = Mockito.mock(CAEntity.class);

        Mockito.when(pkiEntityManager2.getEntity(c)).thenReturn(null);

        try {
            Mockito.when(c.getCertificateAuthority()).thenReturn(null);

            final Map<String, CredentialManagerX509CRL> testCrl = this.certificateManager.getCrl("CN=ENMManagementCA", false, false);
            assertTrue(false);

        } catch (final CredentialManagerCRLServiceException e) {

            assertTrue(true);
        } catch (final Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    @Test
    public void testBadConditionsGetCrl() {

        final MockCACrlManagementService pkiIntCACrlManager2 = Mockito.mock(MockCACrlManagementService.class);
        Field pkiIntCACrlManagerField2 = null;
        try {
            pkiIntCACrlManagerField2 = CertificateManagerImpl.class.getDeclaredField("mockIntCACrlManager");
            pkiIntCACrlManagerField2.setAccessible(true);
            pkiIntCACrlManagerField2.set(this.certificateManager, pkiIntCACrlManager2);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        try {

            Mockito.when(pkiIntCACrlManager2.getCRL("CN=ENMManagementCA", CertificateStatus.ACTIVE, false)).thenReturn(null);

            final Map<String, CredentialManagerX509CRL> testCrl = this.certificateManager.getCrl("CN=ENMManagementCA", false, false);
            assertTrue(false);

        } catch (final CredentialManagerCRLServiceException e) {

            assertTrue(true);
        } catch (final Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }

        try {

            final Map<CACertificateIdentifier, List<CRLInfo>> pkiCrlsMap = null;

            Mockito.when(pkiIntCACrlManager2.getCRL("CN=ENMManagementCA", CertificateStatus.ACTIVE, false)).thenReturn(null);

            final Map<String, CredentialManagerX509CRL> testCrl = this.certificateManager.getCrl("CN=ENMManagementCA", false, false);
            assertTrue(false);

        } catch (final CredentialManagerCRLServiceException e) {

            assertTrue(true);
        } catch (final Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }

        try {

            Mockito.when(pkiIntCACrlManager2.getCRL("CN=ENMManagementCA", CertificateStatus.INACTIVE, false)).thenReturn(null);

            final Map<String, CredentialManagerX509CRL> testCrl = this.certificateManager.getCrl("CN=ENMManagementCA", false, false);
            assertTrue(false);

        } catch (final CredentialManagerCRLServiceException e) {

            assertTrue(true);
        } catch (final Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }

    }

    @Test(expected = CredentialManagerEntityNotFoundException.class)
    public void testRevokeCertificateByEntityNull() throws InvalidSubjectException, MissingMandatoryFieldException, AlgorithmNotFoundException,
            EntityCategoryNotFoundException, InvalidEntityCategoryException, EntityAlreadyExistsException, EntityServiceException,
            InvalidEntityAttributeException, InvalidProfileException, ProfileNotFoundException, CertificateExtensionException,
            UnSupportedCertificateVersion, CANotFoundException, InvalidCAException, InvalidProfileAttributeException, ProfileAlreadyExistsException,
            ProfileServiceException, CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException {
        //first test works
        this.createProfilesOnPKI(true);
        this.createEntityOnPKI("pippo");
        this.certificateManager.RevokeCertificateByEntity("pippo", CredentialManagerRevocationReason.UNSPECIFIED, new Date());

        //second test catching invalid argument exception for entity null
        this.certificateManager.RevokeCertificateByEntity(null, CredentialManagerRevocationReason.UNSPECIFIED, new Date());

    }

    @Test
    public void testRevokeCertificateByEntityNotFound() throws CertificateNotFoundException, ExpiredCertificateException, RevokedCertificateException,
            EntityNotFoundException, RevocationServiceException, CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException,
            EntityAlreadyExistsException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException,
            RootCertificateRevocationException {

        //second test catching exception for entity not existent
        try {
            this.certificateManager.RevokeCertificateByEntity("topolino", CredentialManagerRevocationReason.UNSPECIFIED, new Date());
            assertTrue(false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue(true);
        }
        //other tests, other exceptions
        final RevocationServiceImpl pkiRevokeManager2 = Mockito.mock(RevocationServiceImpl.class);
        Field pkiRevokeManagerField2 = null;
        try {
            pkiRevokeManagerField2 = CertificateManagerImpl.class.getDeclaredField("mockRevokeManager");
            pkiRevokeManagerField2.setAccessible(true);
            pkiRevokeManagerField2.set(this.certificateManager, pkiRevokeManager2);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e2) {
            assertTrue(false);
        }
        final Date fakeDate = new Date();
        Mockito.doThrow(new RootCertificateRevocationException("test")).when(pkiRevokeManager2).revokeEntityCertificates("rootRevocation",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("rootRevocation", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        Mockito.doThrow(new ExpiredCertificateException()).when(pkiRevokeManager2).revokeEntityCertificates("expiredCert",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("expiredCert", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        Mockito.doThrow(new RevokedCertificateException()).when(pkiRevokeManager2).revokeEntityCertificates("exceptionRev",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("exceptionRev", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
        Mockito.doThrow(new CertificateNotFoundException()).when(pkiRevokeManager2).revokeEntityCertificates("certNotFound",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("certNotFound", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(true);
        } catch (final Exception e) {
            assertTrue(false);
        }
        Mockito.doThrow(new RevocationServiceException("test")).when(pkiRevokeManager2).revokeEntityCertificates("revService",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("revService", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }

        Mockito.doThrow(new EntityAlreadyExistsException()).when(pkiRevokeManager2).revokeEntityCertificates("revService",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("revService", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }

        Mockito.doThrow(new InvalidEntityAttributeException()).when(pkiRevokeManager2).revokeEntityCertificates("revService",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("revService", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue(true);
        }

        Mockito.doThrow(new InvalidInvalidityDateException("test")).when(pkiRevokeManager2).revokeEntityCertificates("revService",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("revService", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }

        Mockito.doThrow(new IssuerCertificateRevokedException("test")).when(pkiRevokeManager2).revokeEntityCertificates("revService",
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateByEntity("revService", CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerInternalServiceException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testRevokeCertificateById()
            throws CertificateNotFoundException, ExpiredCertificateException, RevokedCertificateException, EntityNotFoundException,
            InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevocationServiceException,
            RootCertificateRevocationException, CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerExpiredCertificateException, CredentialManagerAlreadyRevokedCertificateException {
        final X500Principal subjDN = new X500Principal("CN=Pippo");
        final X500Principal issuerDN = new X500Principal(" CN=PlutoCA , O= Disney ");

        final CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(subjDN, issuerDN, new BigInteger("" + 10));
        //working test
        this.certificateManager.RevokeCertificateById(certId, CredentialManagerRevocationReason.UNSPECIFIED, new Date());

        //Exceptions
        final RevocationServiceImpl pkiRevokeManager3 = Mockito.mock(RevocationServiceImpl.class);
        Field pkiRevokeManagerField3 = null;
        try {
            pkiRevokeManagerField3 = CertificateManagerImpl.class.getDeclaredField("mockRevokeManager");
            pkiRevokeManagerField3.setAccessible(true);
            pkiRevokeManagerField3.set(this.certificateManager, pkiRevokeManager3);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e2) {
            assertTrue(false);
        }

        this.certificateManager.RevokeCertificateById(certId, CredentialManagerRevocationReason.UNSPECIFIED, new Date());
        Date fakeDate = new Date();
        final X500Principal subjExc = new X500Principal("CN=NotFound");
        final X500Principal issuerExc = new X500Principal("CN=PlutoCA");
        final CredentialManagerCertificateIdentifier certIdExc = new CredentialManagerCertificateIdentifier(subjExc, issuerExc,
                new BigInteger("" + 10));

        final DNBasedCertificateIdentifier dnBaseCertId = new DNBasedCertificateIdentifier();
        dnBaseCertId.setIssuerDN(certIdExc.getIssuerDN().getName());
        dnBaseCertId.setSubjectDN(certIdExc.getSubjectDN().getName());
        dnBaseCertId.setCerficateSerialNumber(certIdExc.getSerialNumber().toString(16));

        Mockito.doThrow(new EntityNotFoundException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId, RevocationReason.UNSPECIFIED,
                fakeDate);
        //EntityNotFoundException
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerCertificateNotFoundException e) {
            assertTrue(true);
        }
        //RootCertificateRevocationException
        fakeDate = new Date();
        Mockito.doThrow(new RootCertificateRevocationException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId,
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }
        //ExpiredCertificateException
        fakeDate = new Date();
        Mockito.doThrow(new ExpiredCertificateException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId,
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerExpiredCertificateException e) {
            assertTrue(true);
        }
        //RevokedCertificateException
        fakeDate = new Date();
        Mockito.doThrow(new RevokedCertificateException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId,
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerAlreadyRevokedCertificateException e) {
            assertTrue(true);
        }
        //CertificateNotFoundException
        fakeDate = new Date();
        Mockito.doThrow(new CertificateNotFoundException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId,
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerCertificateNotFoundException e) {
            assertTrue(true);
        }
        //IssuerNotFoundException
        fakeDate = new Date();
        Mockito.doThrow(new IssuerCertificateRevokedException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId,
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }
        //RevocationServiceException
        fakeDate = new Date();
        Mockito.doThrow(new RevocationServiceException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId,
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }

        Mockito.doThrow(new InvalidEntityAttributeException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId,
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }

        Mockito.doThrow(new InvalidInvalidityDateException("test")).when(pkiRevokeManager3).revokeCertificateByDN(dnBaseCertId,
                RevocationReason.UNSPECIFIED, fakeDate);
        try {
            this.certificateManager.RevokeCertificateById(certIdExc, CredentialManagerRevocationReason.UNSPECIFIED, fakeDate);
            assertTrue(false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }
    }

    @Test
    public void TestListCertificatesEntityNull() throws EntityNotFoundException,
            com.ericsson.oss.services.security.pkimock.exception.MockCertificateServiceException, InvalidSubjectException,
            MissingMandatoryFieldException, AlgorithmNotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException,
            EntityAlreadyExistsException, EntityServiceException, InvalidEntityAttributeException, InvalidProfileException, ProfileNotFoundException,
            CertificateExtensionException, UnSupportedCertificateVersion, CANotFoundException, InvalidCAException, InvalidProfileAttributeException,
            ProfileAlreadyExistsException, ProfileServiceException, CertificateNotFoundException, CertificateServiceException,
            CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException, CredentialManagerEntityNotFoundException,
            CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException {
        this.createProfilesOnPKI(true);
        this.createEntityOnPKI("pippo34");
        List<CredentialManagerX509Certificate> certs = null;
        //first test works (entity)
        certs = this.certificateManager.ListCertificates("pippo34", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE,
                CredentialManagerCertificateStatus.INACTIVE);
        assertNotNull(certs);
        //second test works (CA)
        this.createEntityOnPKI("pluto29CA");
        this.certificateManager.ListCertificates("pluto29CA", CredentialManagerEntityType.CA_ENTITY, CredentialManagerCertificateStatus.INACTIVE);

        //third test entity null invalid
        try {
            this.certificateManager.ListCertificates(null, CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.INACTIVE);
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }

        final PKICACertificateManagementServiceImpl pkiCACertManager3 = Mockito.mock(PKICACertificateManagementServiceImpl.class);
        try {
            final Field pkiIntCACertManagerField3 = CertificateManagerImpl.class.getDeclaredField("mockCACertificateManager");
            pkiIntCACertManagerField3.setAccessible(true);
            pkiIntCACertManagerField3.set(this.certificateManager, pkiCACertManager3);
        } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e1) {
            assertTrue(false);
        }

        Mockito.when(pkiCACertManager3.listCertificates("certNotFound", CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException());
        try {
            this.certificateManager.ListCertificates("certNotFound", CredentialManagerEntityType.CA_ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (final CredentialManagerCertificateNotFoundException e) {
            assertTrue(true);
        }
        Mockito.when(pkiCACertManager3.listCertificates("certServiceExc", CertificateStatus.ACTIVE)).thenThrow(new CertificateServiceException());
        try {
            this.certificateManager.ListCertificates("certServiceExc", CredentialManagerEntityType.CA_ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (final CredentialManagerCertificateServiceException e) {
            assertTrue(true);
        }
        Mockito.when(pkiCACertManager3.listCertificates("invalidEntityAttrExc", CertificateStatus.ACTIVE))
                .thenThrow(new InvalidEntityAttributeException());
        try {
            this.certificateManager.ListCertificates("invalidEntityAttrExc", CredentialManagerEntityType.CA_ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue(true);
        }
    }

    @Test(expected = CredentialManagerInvalidArgumentException.class)
    public void TestListCertificatesCertStatusNull()
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException {
        final CredentialManagerCertificateStatus[] credmStatus = null;
        //certificate status null invalid
        this.certificateManager.ListCertificates("pippo", CredentialManagerEntityType.ENTITY, credmStatus);
    }

    @Test(expected = CredentialManagerInvalidArgumentException.class)
    public void TestListCertificatesEntityTypeInvalid()
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException {
        //entity type invalid
        this.certificateManager.ListCertificates("pippo", CredentialManagerEntityType.ALL, CredentialManagerCertificateStatus.ACTIVE);
    }

    @Test(expected = CredentialManagerEntityNotFoundException.class)
    public void TestListCertificatesEntityNotFound()
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException {
        //entity not found
        this.certificateManager.ListCertificates("pippo", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
    }

    @Test
    public void TestRecordCommand() {
        this.certificateManager.printCommandOnRecorder("test", CommandPhase.FINISHED_WITH_SUCCESS, "junit", "pippo", null);
    }

    @Test
    public void TestRecordError() {
        this.certificateManager.printErrorOnRecorder("test", ErrorSeverity.DEBUG, "junit", "pippo", "additional info");
    }

    @Test
    public void TestListCertificatesSummary()
            throws InvalidSubjectException, MissingMandatoryFieldException, AlgorithmNotFoundException, EntityCategoryNotFoundException,
            InvalidEntityCategoryException, EntityAlreadyExistsException, EntityServiceException, InvalidEntityAttributeException,
            InvalidProfileException, ProfileNotFoundException, CertificateExtensionException, UnSupportedCertificateVersion, CANotFoundException,
            InvalidCAException, InvalidProfileAttributeException, ProfileAlreadyExistsException, ProfileServiceException {

        ////////////////////////////////////////////
        //// first check : ENTITY DOES NOT EXIST////
        ////////////////////////////////////////////
        List<CredentialManagerX500CertificateSummary> credManX500CertSummaryListFirst = null;
        try {
            credManX500CertSummaryListFirst = this.certificateManager.listCertificatesSummary("entityNotExist", CredentialManagerEntityType.ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue("CredentialManagerEntityNotFoundException exception is expected", false);
        } catch (final CredentialManagerEntityNotFoundException e) {
            assertTrue("CredentialManagerEntityNotFoundException is expected", true);
        } catch (final Exception e) {
            assertTrue("These exceptions are not expected", false);
        }
        assertTrue("TestListCertificatesSummary; First Check returned list is not null", credManX500CertSummaryListFirst == null);

        /////////////////////////////////////////////////////////////////////////
        //// second check : Entity exists but Error in Certificate Encoding   ////
        ////                because pki mock certificates have status = null  ////
        ////                ONLY for END Entity.
        /////////////////////////////////////////////////////////////////////////
        this.createProfilesOnPKI(true);
        this.createEntityOnPKI("EntityExist");
        List<CredentialManagerX500CertificateSummary> credManX500CertSummaryListSecond = null;
        try {
            credManX500CertSummaryListSecond = this.certificateManager.listCertificatesSummary("EntityExist", CredentialManagerEntityType.ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue("CredentialManagerCertificateEncodingException exception is expected", false);
        } catch (final CredentialManagerCertificateEncodingException e) {
            assertTrue("CredentialManagerCertificateEncodingException expected", true);
        } catch (final Exception e) {
            assertTrue("These exceptions are not expected", false);
        }
        assertTrue("second check : returned list is not null", credManX500CertSummaryListSecond == null);

        ////////////////////////////////////////////////////
        //// third check : entityName parameter is null ////
        ////////////////////////////////////////////////////
        List<CredentialManagerX500CertificateSummary> credManX500CertSummaryListThird = null;
        try {
            credManX500CertSummaryListThird = this.certificateManager.listCertificatesSummary(null, CredentialManagerEntityType.ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue("CredentialManagerInvalidArgumentException expected", false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue("CredentialManagerInvalidArgumentException expected", true);
        } catch (final Exception e) {
            assertTrue("These exceptions are not expected", false);
        }
        assertTrue("third check : returned list is not null", credManX500CertSummaryListThird == null);

        /////////////////////////////////////////////////////////////
        //// fourth check : certificate status parameter is null ////
        /////////////////////////////////////////////////////////////
        List<CredentialManagerX500CertificateSummary> credManX500CertSummaryListFourth = null;
        final CredentialManagerCertificateStatus[] credmStatus = null;
        try {
            credManX500CertSummaryListFourth = this.certificateManager.listCertificatesSummary("EntityExist", CredentialManagerEntityType.ENTITY,
                    credmStatus);
            assertTrue("CredentialManagerInvalidArgumentException expected", false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue("CredentialManagerInvalidArgumentException expected", true);
        } catch (final Exception e) {
            assertTrue("These exceptions are not expected", false);
        }
        assertTrue("fourth check : returned list is not null", credManX500CertSummaryListFourth == null);

        //////////////////////////////////////////////////////
        //// fifth check : entity type parameter is wrong ////
        //////////////////////////////////////////////////////
        List<CredentialManagerX500CertificateSummary> credManX500CertSummaryListFifth = null;
        try {
            credManX500CertSummaryListFifth = this.certificateManager.listCertificatesSummary("EntityExist", CredentialManagerEntityType.ALL,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue("CredentialManagerInvalidArgumentException expected", false);
        } catch (final CredentialManagerInvalidArgumentException e) {
            assertTrue("CredentialManagerInvalidArgumentException expected", true);
        } catch (final Exception e) {
            assertTrue("These exceptions are not expected", false);
        }
        assertTrue("fifth check : returned list is not null", credManX500CertSummaryListFifth == null);

        ///////////////////////////////////////////////////////////////////////////
        //// sixth check :  CA Entity exists and all works fine                 ////
        ///////////////////////////////////////////////////////////////////////////
        this.createEntityOnPKI("CaEntityExist");
        List<CredentialManagerX500CertificateSummary> credManX500CertSummaryListSixth = null;
        try {
            credManX500CertSummaryListSixth = this.certificateManager.listCertificatesSummary("CaEntityExist", CredentialManagerEntityType.CA_ENTITY,
                    CredentialManagerCertificateStatus.ACTIVE);
            assertTrue("Exceptions are NOT expected", true);
        } catch (final Exception e) {
            assertTrue("Exceptions are not expected", false);
        }
        assertTrue("sixth check : returned list is null", credManX500CertSummaryListSixth != null);
        assertTrue("sixth check : returned list has wrong size", credManX500CertSummaryListSixth.size() == 3);
        assertTrue("sixth check : first element of list has wrong issuer DN",
                credManX500CertSummaryListSixth.get(0).getIssuerX500Principal().getName().startsWith("CN=ENMInfrastructureCA"));
    }

    private PKCS10CertificationRequest createCSR(final KeyPair keyPair, final String sigAlgName, final String subjectCommonName) {
        PKCS10CertificationRequest csr = null;
        final Entity entity = new Entity();
        final Subject subject = new Subject();
        final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();
        subjectMap.put(SubjectFieldType.COMMON_NAME, subjectCommonName);

        for (final Entry<SubjectFieldType, String> entry : subjectMap.entrySet()) {
            final SubjectField subFieldTemp = new SubjectField();
            subFieldTemp.setType(entry.getKey());
            subFieldTemp.setValue(entry.getValue());
            subject.getSubjectFields().add(subFieldTemp);
        }

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setSubject(subject);
        entityInfo.setName(subjectCommonName);
        entity.setEntityInfo(entityInfo);

        final Vector<GeneralName> entries = new Vector<GeneralName>();
        entries.add(new GeneralName(GeneralName.dNSName, "localhost"));
        final GeneralName[] names = new GeneralName[entries.size()];
        entries.copyInto(names);

        final GeneralNames generalNames = new GeneralNames(names);

        final ExtensionsGenerator extGen = new ExtensionsGenerator();

        try {
            extGen.addExtension(Extension.subjectAlternativeName, false, generalNames);
        } catch (final IOException e) {
            // TODO LOG ERROR
            e.printStackTrace();
        }

        final Extensions extensions = extGen.generate();
        final Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));

        final Attribute[] att = new Attribute[1];
        att[0] = attribute;

        csr = this.getCSR(entity, sigAlgName, keyPair, att);

        return csr;
    }

    private PKCS10CertificationRequest getCSR(final Entity eentity, final String signatureAlgorithm, final KeyPair keyPair,
                                              final Attribute[] attributes) {

        try {
            final PKCS10CertificationRequest csr = CertificateUtils.generatePKCS10Request(signatureAlgorithm, eentity, keyPair, (attributes), null);

            return csr;

        } catch (final Exception e) {

            //throw new CredentialManagerServiceException();
        }
        return null;
    }

    private void createEntityOnPKI(final String entityName) {
        try {
            final Entity entity = new Entity();
            final EntityProfile entityProfile = new EntityProfile();
            entity.setEntityProfile(entityProfile);
            entity.getEntityProfile().setName("myEntityProfile");
            final Algorithm algorithm = new Algorithm();
            entity.setKeyGenerationAlgorithm(algorithm);
            final EntityInfo entityInfo = new EntityInfo();
            final Map<SubjectFieldType, String> subjectDN = new HashMap<SubjectFieldType, String>();
            subjectDN.put(SubjectFieldType.COMMON_NAME, "mara");
            final Subject subject = new Subject();

            for (final Entry<SubjectFieldType, String> entry : subjectDN.entrySet()) {
                final SubjectField subFieldTemp = new SubjectField();
                subFieldTemp.setType(entry.getKey());
                subFieldTemp.setValue(entry.getValue());
                subject.getSubjectFields().add(subFieldTemp);
            }

            entityInfo.setSubject(subject);
            entityInfo.setName(entityName);

            final EntityCategory category = new EntityCategory();
            category.setName("SERVICE");
            entity.setCategory(category);

            entity.setEntityInfo(entityInfo);

            this.pkiEntityManager.createEntity(entity);
        } catch (InvalidSubjectAltNameExtension | InvalidSubjectException | MissingMandatoryFieldException | AlgorithmNotFoundException
                | EntityCategoryNotFoundException | InvalidEntityCategoryException | CRLExtensionException | CRLGenerationException
                | EntityAlreadyExistsException | EntityServiceException | InvalidCRLGenerationInfoException | InvalidEntityException
                | InvalidEntityAttributeException | InvalidProfileException | ProfileNotFoundException | UnsupportedCRLVersionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void createProfilesOnPKI(final boolean trustCreate) {
        try {
            CertificateProfile certificateProfile = new CertificateProfile();
            final CertificateAuthority certauthority = new CertificateAuthority();
            final CAEntity caent1 = new CAEntity();
            caent1.setCertificateAuthority(certauthority);
            certificateProfile.setIssuer(caent1);
            certificateProfile.getIssuer().getCertificateAuthority().setName("DEFAULT");
            certificateProfile.setName("myCertificateProfile");
            certificateProfile.setType(ProfileType.CERTIFICATE_PROFILE);

            Duration validity = null;
            try {
                validity = DatatypeFactory.newInstance().newDuration("P365D");
            } catch (final DatatypeConfigurationException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            certificateProfile.setCertificateValidity(validity);

            final Algorithm sigAlg = new Algorithm();
            sigAlg.setKeySize(2048);
            sigAlg.setName("sigAlg");
            certificateProfile.setSignatureAlgorithm(sigAlg);

            certificateProfile = this.pkiProfileManager.createProfile(certificateProfile);

            TrustProfile trustProfile = new TrustProfile();
            final List<String> internalCAs = new ArrayList<String>();
            internalCAs.add("ENMManagementCA");

            final CertificateAuthority certauthority1 = new CertificateAuthority();
            final CAEntity caent2 = new CAEntity();
            caent2.setCertificateAuthority(certauthority1);
            final List<TrustCAChain> trustcachainlist = new ArrayList<TrustCAChain>();
            final TrustCAChain trustcachain1 = new TrustCAChain();
            trustcachain1.setInternalCA(caent2);
            trustcachainlist.add(trustcachain1);
            trustProfile.setTrustCAChains(trustcachainlist);

            trustProfile.getTrustCAChains().get(0).getInternalCA().getCertificateAuthority().setName("ENMManagementCA");

            final List<String> externalCAs = new ArrayList<String>();
            externalCAs.add("EricssonCA");
            //trustProfile.setExternalCAs(externalCAs);

            trustProfile.setName("myTrustProfile");

            trustProfile.setType(ProfileType.TRUST_PROFILE);
            if (trustCreate) {
                trustProfile = this.pkiProfileManager.createProfile(trustProfile);
            }

            EntityProfile entityProfile = new EntityProfile();
            entityProfile.setCertificateProfile(certificateProfile);
            entityProfile.getCertificateProfile().setName(certificateProfile.getName());
            entityProfile.setName("myEntityProfile");
            entityProfile.setType(ProfileType.ENTITY_PROFILE);
            final Subject subject = new Subject();
            final Map<SubjectFieldType, String> subjectDN = new HashMap<SubjectFieldType, String>();
            subjectDN.put(SubjectFieldType.DN_QUALIFIER, "subjectProfile");

            for (final Entry<SubjectFieldType, String> entry : subjectDN.entrySet()) {
                final SubjectField subFieldTemp = new SubjectField();
                subFieldTemp.setType(entry.getKey());
                subFieldTemp.setValue(entry.getValue());
                subject.getSubjectFields().add(subFieldTemp);
            }

            entityProfile.setSubject(subject);
            final List<String> trustProfileList = new ArrayList<String>();
            trustProfileList.add(trustProfile.getName());

            entityProfile.getTrustProfiles().add(trustProfile);

            entityProfile = this.pkiProfileManager.createProfile(entityProfile);
        } catch (CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException | UnSupportedCertificateVersion
                | AlgorithmNotFoundException | CANotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | InvalidProfileAttributeException | ProfileAlreadyExistsException | ProfileNotFoundException
                | ProfileServiceException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void deleteProfilesOnPKI(final boolean isTrustCreate) throws ProfileInUseException, ProfileNotFoundException, ProfileServiceException {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName("myCertificateProfile");
        this.pkiProfileManager.deleteProfile(certificateProfile);

        if (isTrustCreate) {
            final TrustProfile trustProfile = new TrustProfile();
            trustProfile.setName("myTrustProfile");
            this.pkiProfileManager.deleteProfile(trustProfile);
        }

        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName("myEntityProfile");
        this.pkiProfileManager.deleteProfile(entityProfile);
    }

    public static byte[] encode(final ASN1Encodable encodable) throws CertificateEncodingException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            ASN1OutputStream.create(baos, ASN1Encoding.DER).writeObject(encodable);
        } catch (final IOException ex) {
            throw new CertificateEncodingException("Cannot encode: " + ex.toString());
        }
        return baos.toByteArray();
    }

    //DU: Fallback solution for PKI External CA
    @Test
    public void testGetTrustForVC_Root_CA_A1() throws CertificateEncodingException, CredentialManagerServiceException {

        final CredentialManagerCertificateAuthority ca = this.certificateManager
                .getTrustCertificates(new CredentialManagerTrustCA("VC_Root_CA_A1", false), true);

        assertNotNull(ca);
        assertEquals(0, ca.getCACertificateChain().size());
    }

}
