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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper.channelMode;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapperFactory;
import com.ericsson.oss.itpf.security.credmsapi.CredentialManagerProfileType;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.AlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetEndEntitiesByCategoryException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCategoryNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCertificateFormatException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReIssueLegacyXMLCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReissueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeEntityCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateSummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtensionImpl;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntitySummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustSource;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.Base64Writer;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.JKSWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerAlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
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
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

@RunWith(MockitoJUnitRunner.class)
public class IfCertificateManagementImplTest {
    private static final Logger LOG = LogManager.getLogger(IfCertificateManagementImplTest.class);

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmsapi.business.IfCertificateManagementImpl#issueCertificate(com.ericsson.oss.itpf.security.credmsapi.api.model.UserInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo)}
     * .
     */
    EntityInfo entityInfo = new EntityInfo();

    KeystoreInfo ksInfo = new KeystoreInfo(null, null, null, null, null, null, null);

    TrustStoreInfo tsInfo = new TrustStoreInfo(null, null, null, null, null, null);

    TrustStoreInfo crlInfo = new TrustStoreInfo(null, null, null, null, null, null);

    String xmlSubject = "O=OpenDJ, CN=Administrator";

    //////////////////////////////////////////////////////
    @InjectMocks
    // (answer=Answers.CALLS_REAL_METHODS)
    IfCertificateManagementImpl ifCertMngtMock;
    @Mock
    CredMServiceWrapperFactory mockWrapperFactory;
    @Mock
    CredMServiceWrapper mockWrapper;

    //    @Mock
    //    CertificateManager mockCertificateManager;

    ///////////////////////////////////////////////////////////////////////

    //
    // MOCK DEFINITION
    //
    private void mockTheService() {
        /**
         * MOCK ifCertMngtMock
         */
        //prepare data for Entity
        final CredentialManagerEntity mockEntityInfo = PrepareCertificate.prepareEntity();

        //prepare data for Profile
        final CredentialManagerProfileInfo mockProfile = PrepareCertificate.prepareProfileInfo();
        ;

        // prepare data for Certificate
        final X509Certificate mockCaCert = PrepareCertificate.prepareCertificate();

        // prepare data for Trust
        final CredentialManagerTrustMaps mockTrustMap = PrepareCertificate.prepareTrust();

        // prepare data for CRL
        final CredentialManagerCrlMaps mockCrlMap = PrepareCertificate.generateCrl();

        CredentialManagerPIBParameters parameters = new CredentialManagerPIBParameters();
        parameters.setServiceCertAutoRenewalEnabled(true);
        parameters.setServiceCertAutoRenewalTimer(2);
        parameters.setServiceCertAutoRenewalWarnings("20,10,5");
        when(this.mockWrapper.getPibParameters()).thenReturn(parameters);

        // mock the wrapperFactory in order to return the mocked wrapper
        try {
            when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenReturn(this.mockWrapper);
        } catch (final Exception e1) {
            e1.printStackTrace();
        }

        //
        // mock the Wrapper:
        //
        // getEntity
        when(this.mockWrapper.getEntity(Matchers.anyString())).thenReturn(mockEntityInfo);

        // getExistingEntity existingEntity
        when(this.mockWrapper.getExistingEntity(Matchers.contains("entityName"))).thenReturn(mockEntityInfo);

        // getExistingEntity notExistingEntity
        when(this.mockWrapper.getExistingEntity(Matchers.contains("notExistingEntity"))).thenThrow(new CredentialManagerEntityNotFoundException());

        // getExistingEntity internal error
        when(this.mockWrapper.getExistingEntity(Matchers.contains("internalErrorEntity"))).thenReturn(null);

        // getProfile
        when(this.mockWrapper.getProfile()).thenReturn(mockProfile);
        when(this.mockWrapper.getProfile(Matchers.anyString())).thenReturn(mockProfile);

        // isOTPValid
        when(this.mockWrapper.isOTPValid(Matchers.anyString(), Matchers.anyString())).thenReturn(true);

        // createAndGetEndEntity
        try {
            when(this.mockWrapper.createAndGetEndEntity(Matchers.anyString(), Matchers.anyString())).thenReturn(mockEntityInfo);
            when(
                    this.mockWrapper.createAndGetEntity(Matchers.anyString(), Matchers.any(CredentialManagerSubject.class), Matchers.any(CredentialManagerSubjectAltName.class),
                            Matchers.any(CredentialManagerAlgorithm.class), Matchers.anyString())).thenReturn(mockEntityInfo);
        } catch (final Exception e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        //this.mockWrapper.checkCurrentTrust(entityProfileName, currentTrust, source)

        // getCertificate
        // getCertificateChain
        CredentialManagerX509Certificate CMcaCert = null;
        CredentialManagerX509Certificate[] CMcaCertChain = null;
        try {
            CMcaCert = new CredentialManagerX509Certificate(mockCaCert);
            CMcaCertChain = new CredentialManagerX509Certificate[] { CMcaCert };
            when(this.mockWrapper.getCertificate(Matchers.any(PKCS10CertificationRequest.class))).thenReturn(CMcaCertChain);
            when(this.mockWrapper.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString())).thenReturn(CMcaCertChain);
            //when(this.mockWrapper.getCertificateChain(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.anyBoolean())).thenReturn(CMcaCertChain);

        } catch (final Exception e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        // getTrustCertificates
        when(this.mockWrapper.getTrustCertificates(Matchers.anyString(), Matchers.any(CredentialManagerProfileType.class))).thenReturn(mockTrustMap);
        when(this.mockWrapper.checkCurrentTrust(Matchers.anyString(), Matchers.any(CredentialManagerProfileType.class), Matchers.any(SortedSet.class), Matchers.any(TrustSource.class))).thenReturn(
                mockTrustMap);

        // getCRLs
        try {
            when(this.mockWrapper.getCRLs(Matchers.anyString(), Matchers.any(CredentialManagerProfileType.class))).thenReturn(mockCrlMap);
        } catch (final Exception e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        // revokeCertificateById
        final Boolean revokeResult = true;
        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class))).thenReturn(revokeResult);
        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class)))
                .thenReturn(revokeResult);

        try {
            Mockito.doNothing().when(this.mockWrapper).revokeCertificateByEntity(Matchers.anyString(), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));
        } catch (final RevokeCertificateException | EntityNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // getEndEntitiesByCategory
        // incomplete entity (no Subject set)
        final Set<CredentialManagerEntity> setOfWrongEntities = new HashSet<CredentialManagerEntity>();
        final CredentialManagerEntity cmWrongEntity = new CredentialManagerEntity();
        cmWrongEntity.setName("wrongEntity");
        cmWrongEntity.setId(1);
        cmWrongEntity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        setOfWrongEntities.add(cmWrongEntity);

        // complete entity
        final Set<CredentialManagerEntity> setOfEntities = new HashSet<CredentialManagerEntity>();
        final CredentialManagerEntity cmEntity = new CredentialManagerEntity();
        cmEntity.setName("realEntity");
        cmEntity.setId(1);
        cmEntity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setCommonName("CN=common");
        subject.setCountryName("C=IT");
        cmEntity.setSubject(subject);
        setOfEntities.add(cmEntity);

        when(this.mockWrapper.getEntitiesByCategory(Matchers.startsWith("real"))).thenReturn(setOfEntities);
        when(this.mockWrapper.getEntitiesByCategory(Matchers.startsWith("wrong"))).thenReturn(setOfWrongEntities);
        when(this.mockWrapper.getEntitiesByCategory(Matchers.startsWith("empty"))).thenReturn(null);
        when(this.mockWrapper.getEntitiesByCategory(Matchers.startsWith("exception"))).thenThrow(new CredentialManagerInternalServiceException());
        when(this.mockWrapper.getEntitiesByCategory(Matchers.startsWith("notFound"))).thenThrow(new CredentialManagerInvalidArgumentException());
        when(this.mockWrapper.getEntitiesSummaryByCategory(Matchers.startsWith("real"))).thenReturn(setOfEntities);
        when(this.mockWrapper.getEntitiesSummaryByCategory(Matchers.startsWith("wrong"))).thenReturn(setOfWrongEntities);
        when(this.mockWrapper.getEntitiesSummaryByCategory(Matchers.startsWith("empty"))).thenReturn(null);
        when(this.mockWrapper.getEntitiesSummaryByCategory(Matchers.startsWith("exception"))).thenThrow(new CredentialManagerInternalServiceException());
        when(this.mockWrapper.getEntitiesSummaryByCategory(Matchers.startsWith("notFound"))).thenThrow(new CredentialManagerInvalidArgumentException());

        ///////////////////////////////////////////////
        /////////// getCertificatesByEntityName ///////
        ///////////////////////////////////////////////

        //// first check
        List<CredentialManagerX500CertificateSummary> certsSummaryList_1 = new ArrayList<CredentialManagerX500CertificateSummary>();

        X500Principal issuerDN_1 = new X500Principal("CN=issuerFirst");
        X500Principal subjectDN_1 = new X500Principal("CN=subjectFirst");
        BigInteger certificateSn_1 = new BigInteger("123456789");
        CredentialManagerCertificateStatus certStatus_1 = CredentialManagerCertificateStatus.ACTIVE;
        CredentialManagerX500CertificateSummary certSum_1 = new CredentialManagerX500CertificateSummary(subjectDN_1, issuerDN_1, certificateSn_1, certStatus_1);

        certsSummaryList_1.add(certSum_1);

        try {
            //// first check
            when(this.mockWrapper.getCertificatesByEntityName(Matchers.matches("realEntity"), Matchers.eq(CredentialManagerEntityType.ENTITY), Matchers.eq(CredentialManagerCertificateStatus.ACTIVE)))
                    .thenReturn(certsSummaryList_1);

            //// second check 
            when(this.mockWrapper.getCertificatesByEntityName(Matchers.matches("GenericEx"), Matchers.eq(CredentialManagerEntityType.ENTITY), Matchers.eq(CredentialManagerCertificateStatus.ACTIVE)))
                    .thenThrow(new GetCertificatesByEntityNameException());

            //// third check
            when(
                    this.mockWrapper.getCertificatesByEntityName(Matchers.matches("CertNotFoundEx"), Matchers.eq(CredentialManagerEntityType.ENTITY),
                            Matchers.eq(CredentialManagerCertificateStatus.ACTIVE))).thenThrow(new CertificateNotFoundException());

            //// fourth check
            when(
                    this.mockWrapper.getCertificatesByEntityName(Matchers.matches("EntNotFoundEx"), Matchers.eq(CredentialManagerEntityType.ENTITY),
                            Matchers.eq(CredentialManagerCertificateStatus.ACTIVE))).thenThrow(new EntityNotFoundException());

        } catch (CertificateNotFoundException | GetCertificatesByEntityNameException | EntityNotFoundException e) {
            e.printStackTrace();
        }

    }

    //    private void mockTheServiceBuilder() {
    //        // mock the wrapperFactory in order to return the mocked wrapper
    //        try {
    //            when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenReturn(this.mockWrapper);
    //        } catch (final Exception e1) {
    //            e1.printStackTrace();
    //        }
    //    }

    @Test
    public void testIssueCertificateFromAService() {

        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            ifCertMngt.issueCertificate(this.entityInfo, this.ksInfo);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("entityInfo is NULL or its fields empty"));
        } catch (final EntityNotFoundException e) {
            assertTrue(e.getMessage().contains("Error occurred while retrieving"));
        } catch (final InvalidCertificateFormatException e) {
            assertTrue(e.getMessage().contains("Invalid certificate format, it must be PKCS12"));
        } catch (OtpNotValidException e) {
            assertTrue("Exception not expected", false);
        } catch (OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }

        if (this.entityInfo.getEntityName() == null) {
            this.entityInfo.setEntityName("testentityname");
        }
        if (this.entityInfo.getOneTimePassword() == null) {
            this.entityInfo.setOneTimePassword("oneTimePassword");
        }

        try {
            ifCertMngt.issueCertificate(this.entityInfo, this.ksInfo);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("ksInfo is NULL or empty"));
        } catch (final EntityNotFoundException e) {
            assertTrue(e.getMessage().contains("Error occurred while retrieving"));
        } catch (final InvalidCertificateFormatException e) {
            assertTrue(e.getMessage().contains("Invalid certificate format, it must be PKCS12"));
        } catch (OtpNotValidException e) {
            assertTrue("Exception not expected", false);
        } catch (OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }

        if (this.ksInfo.getKeyAndCertLocation() == null) {
            this.ksInfo.setKeyAndCertLocation("/tmp/keystore.p12");
        }
        if (this.ksInfo.getKeyStorePwd() == null) {
            this.ksInfo.setKeyStorePwd("keyStorePwd");
        }
        if (this.ksInfo.getCertFormat() == null) {
            this.ksInfo.setCertFormat(CertificateFormat.PKCS12);
        }
        if (this.ksInfo.getAlias() == null) {
            this.ksInfo.setAlias("alias");
        }

        try {
            ifCertMngt.issueCertificate(this.entityInfo, this.ksInfo);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("could not resolve the JNDI"));
        } catch (final EntityNotFoundException e) {
            assertTrue(e.getMessage().contains("Error occurred while retrieving"));
        } catch (final InvalidCertificateFormatException e) {
            assertTrue(e.getMessage().contains("Invalid certificate format, it must be PKCS12"));
        } catch (OtpNotValidException e) {
            assertTrue("Exception not expected", false);
        } catch (OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }

        this.ksInfo.setCertFormat(CertificateFormat.BASE_64);

        try {
            ifCertMngt.issueCertificate(this.entityInfo, this.ksInfo);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("could not resolve the JNDI"));
        } catch (final EntityNotFoundException e) {
            assertTrue(e.getMessage().contains("Error occurred while retrieving"));
        } catch (final InvalidCertificateFormatException e) {
            assertTrue(e.getMessage().contains("Invalid certificate format, it must be PKCS12"));
        } catch (OtpNotValidException e) {
            assertTrue("Exception not expected", false);
        } catch (OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }
    }

    @Test
    public void testMockedIssueCertificateFromAService() {

        this.mockTheService();

        this.entityInfo.setEntityName("testentityname");
        this.entityInfo.setOneTimePassword("oneTimePassword");
        this.ksInfo.setKeyAndCertLocation("/tmp/keystore.p12");
        this.ksInfo.setKeyStorePwd("keyStorePwd");
        this.ksInfo.setCertFormat(CertificateFormat.PKCS12);
        this.ksInfo.setAlias("alias");
        //////////////////////////////          
        //
        //        TEST
        //      
        //////////////////////////////   

        boolean result = false;
        try {
            result = this.ifCertMngtMock.issueCertificate(this.entityInfo, this.ksInfo);
        } catch (final Exception e) {
            // TODO Auto-generated catch block
            //e.printStackTrace();
        }
        assertTrue("issueCertificate", result);

        // Reissue certificate with existing key store
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(this.entityInfo, this.ksInfo, CrlReason.CA_COMPROMISE);
        } catch (final ReissueCertificateException e) {
        } catch (final EntityNotFoundException e) {
        } catch (final InvalidCertificateFormatException e) {
        } catch (OtpNotValidException e) {
            assertTrue("Exception not expected", false);
        } catch (OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }
        assertTrue("reIssueCertificate with key store ", result);

        // delete the file
        final File ksFile = new File("/tmp/keystore.p12");
        ksFile.delete();

        // Test reissue without key store
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(this.entityInfo, this.ksInfo, CrlReason.CA_COMPROMISE);
        } catch (final ReissueCertificateException e) {
        } catch (final EntityNotFoundException e) {
        } catch (final InvalidCertificateFormatException e) {
        } catch (OtpNotValidException e) {
            assertTrue("Exception not expected", false);
        } catch (OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }
        assertTrue("reIssueCertificate without key store ", result);

        // Test reissue with empty entity name
        this.entityInfo.setEntityName("");
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(this.entityInfo, this.ksInfo, CrlReason.CA_COMPROMISE);
        } catch (final ReissueCertificateException e) {
        } catch (final EntityNotFoundException e) {
        } catch (final InvalidCertificateFormatException e) {
        } catch (OtpNotValidException e) {
            assertTrue("Exception not expected", false);
        } catch (OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }
        assertFalse("reIssueCertificate with entity name empty ", result);

        // delete the file
        ksFile.delete();
    }

    @Test
    public void testMockedReissueXmlLegacyCertificate() {

        this.mockTheService();

        this.entityInfo.setEntityName("testentityname");
        this.entityInfo.setOneTimePassword("oneTimePassword");

        this.ksInfo.setCertFormat(CertificateFormat.LEGACY_XML);

        final String certFileName = "/tmp/keystore.xml";
        final String keyEncrPwdFileName = "src/main/resources/keyEncrPwdFile.txt";

        // delete the file
        final File ksFile = new File(certFileName);
        ksFile.delete();

        ///////////////////////////////////          
        //
        // TEST (no certificate to revoke)
        //      
        ///////////////////////////////////          

        boolean result = false;
        try {
            result = this.ifCertMngtMock.reIssueLegacyXMLCertificate(this.entityInfo, certFileName, true, null, CrlReason.CA_COMPROMISE);
        } catch (ReIssueLegacyXMLCertificateException | EntityNotFoundException | OtpNotValidException | OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }

        assertTrue("reIssueLegacyXMLCertificate with key store ", result);

        /////
        //
        // TEST (same with empty password)
        //
        /////

        result = false;
        try {
            result = this.ifCertMngtMock.reIssueLegacyXMLCertificate(this.entityInfo, certFileName, true, "", CrlReason.CA_COMPROMISE);
        } catch (ReIssueLegacyXMLCertificateException | EntityNotFoundException | OtpNotValidException | OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }

        assertTrue("reIssueLegacyXMLCertificate with key store ", result);

        /////////////////////////////////////////          
        //
        // TEST (previous certificate to revoke)
        //      
        /////////////////////////////////////////          
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueLegacyXMLCertificate(this.entityInfo, certFileName, true, keyEncrPwdFileName, CrlReason.CA_COMPROMISE);
        } catch (ReIssueLegacyXMLCertificateException | EntityNotFoundException | OtpNotValidException | OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }

        assertTrue("reIssueLegacyXMLCertificate with key store ", result);

        /////////////////////////////////////////          
        //
        // TEST (certificate chain null)
        //      
        /////////////////////////////////////////          
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueLegacyXMLCertificate(this.entityInfo, certFileName, null, keyEncrPwdFileName, CrlReason.CA_COMPROMISE);
            assertTrue("Exception expected", false);
        } catch (ReIssueLegacyXMLCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("invalid chain parameter"));
        } catch (EntityNotFoundException | OtpNotValidException | OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }

        /////////////////////////////////////////          
        //
        // TEST (input file not found)
        //      
        /////////////////////////////////////////          
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueLegacyXMLCertificate(this.entityInfo, certFileName, true, "keyEncrPwdFileNotFound.txt", CrlReason.CA_COMPROMISE);
            assertTrue("Exception expected", false);
        } catch (ReIssueLegacyXMLCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("Password file not found"));
        } catch (EntityNotFoundException | OtpNotValidException | OtpExpiredException e) {
            assertTrue("Exception not expected", false);
        }

        //////////////////////////////////////////////          
        //
        // TEST (exception due to revocation failure)
        //      
        //////////////////////////////////////////////          

        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class)))
                .thenThrow(new CredentialManagerAlreadyRevokedCertificateException("certificate already revoked"));

        result = false;
        try {
            result = this.ifCertMngtMock.reIssueLegacyXMLCertificate(this.entityInfo, certFileName, true, keyEncrPwdFileName, CrlReason.CA_COMPROMISE);
            assertTrue("reIssueLegacyXMLCertificate: exception expected", false);
        } catch (ReIssueLegacyXMLCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("certificate already revoked"));
        } catch (Exception e) {
            assertTrue("Exception not expected", false);
        }

        /////////////////////////////////////////          
        //
        // TEST (exception due to profile null)
        //      
        /////////////////////////////////////////          

        // profile null
        when(mockWrapper.getProfile(Matchers.anyString())).thenReturn(null);

        result = false;
        try {
            result = this.ifCertMngtMock.reIssueLegacyXMLCertificate(this.entityInfo, certFileName, true, keyEncrPwdFileName, CrlReason.CA_COMPROMISE);
            assertTrue("reIssueLegacyXMLCertificate: exception expected", false);
        } catch (ReIssueLegacyXMLCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("Error while reissuing a certificate"));
        } catch (Exception e) {
            assertTrue("Exception not expected", false);
        }

        // delete the file
        ksFile.delete();
    }

    @Test
    public void testMockedIssueCertificateFromAServiceExc() {

        this.mockTheService();

        this.entityInfo.setEntityName("testentityname");
        this.entityInfo.setOneTimePassword("oneTimePassword");
        this.ksInfo.setKeyAndCertLocation("/tmp/keystore.p12");
        this.ksInfo.setKeyStorePwd("keyStorePwd");
        this.ksInfo.setCertFormat(CertificateFormat.PKCS12);
        this.ksInfo.setAlias("alias");

        //////////////////////////////          
        //
        //        TEST entity exc
        //      
        //////////////////////////////   

        // entity null
        when(mockWrapper.getEntity(Matchers.anyString())).thenReturn(null);

        try {
            this.ifCertMngtMock.issueCertificate(this.entityInfo, this.ksInfo);
            assertTrue("Exception expected", false);
        } catch (final EntityNotFoundException e) {
            assertTrue("Exception expected", true);
        } catch (Exception e) {
            assertTrue("Unexpected Exception occurred" + e.getMessage(), false);
        }

        //prepare data for Entity
        final CredentialManagerEntity mockEntityInfo = PrepareCertificate.prepareEntity();
        when(mockWrapper.getEntity(Matchers.anyString())).thenReturn(mockEntityInfo);

        //////////////////////////////          
        //
        //        TEST profile exc
        //      
        //////////////////////////////   

        // profile null
        when(mockWrapper.getProfile(Matchers.anyString())).thenReturn(null);

        try {
            this.ifCertMngtMock.issueCertificate(this.entityInfo, this.ksInfo);
            assertTrue("Exception expected", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("Error occurred while retrieving " + mockEntityInfo.getEntityProfileName() + " profile"));
        } catch (Exception e) {
            assertTrue("Unexpected Exception occurred" + e.getMessage(), false);
        }

        //prepare data for Profile
        final CredentialManagerProfileInfo mockProfile = PrepareCertificate.prepareProfileInfo();
        when(mockWrapper.getProfile(Matchers.anyString())).thenReturn(mockProfile);

        //////////////////////////////          
        //
        //        TEST Cert exc
        //      
        //////////////////////////////

        try {
            when(this.mockWrapper.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.contains("testentityname"), Matchers.anyBoolean(), Matchers.anyString())).thenThrow(
                    new IssueCertificateException());
        } catch (IssueCertificateException | OtpExpiredException | OtpNotValidException e) {
            assertTrue("Unexpected Exception occurred" + e.getMessage(), false);
        }

        try {
            this.ifCertMngtMock.issueCertificate(this.entityInfo, this.ksInfo);
            assertTrue("Exception expected", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception expected", true);
        } catch (Exception e) {
            assertTrue("Unexpected Exception occurred" + e.getMessage(), false);
        }

        this.entityInfo.setEntityName("newEntityName");

        // prepare data for Certificate
        final X509Certificate mockCaCert = PrepareCertificate.prepareCertificate();
        CredentialManagerX509Certificate CMcaCert = null;
        CredentialManagerX509Certificate[] CMcaCertChain = null;
        try {
            CMcaCert = new CredentialManagerX509Certificate(mockCaCert);
            CMcaCertChain = new CredentialManagerX509Certificate[] { CMcaCert };
            when(this.mockWrapper.getCertificate(Matchers.any(PKCS10CertificationRequest.class))).thenReturn(CMcaCertChain);
            when(this.mockWrapper.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.contains("newEntityName"), Matchers.anyBoolean(), Matchers.anyString())).thenReturn(
                    CMcaCertChain);

        } catch (final Exception e) {
            assertTrue("Unexpected Exception occurred" + e.getMessage(), false);
        }

        //////////////////////////////          
        //
        //        TEST Trust exception
        //      
        //////////////////////////////

        when(this.mockWrapper.getTrustCertificates(Matchers.anyString(), Matchers.any(CredentialManagerProfileType.class))).thenReturn(null);

        try {
            this.ifCertMngtMock.issueCertificate(this.entityInfo, this.ksInfo);
            assertTrue("Exception expected", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("trustHandler exception"));
        } catch (Exception e) {
            assertTrue("Unexpected Exception occurred" + e.getMessage(), false);
        }
    }

    @Test
    public void testMockedReIssueCertificateFromAServiceExc() {
        this.mockTheService();

        this.entityInfo.setEntityName("testentityname");
        this.entityInfo.setOneTimePassword("oneTimePassword");
        this.ksInfo.setKeyAndCertLocation("/tmp/keystore.p12");
        this.ksInfo.setKeyStorePwd("keyStorePwd");
        this.ksInfo.setCertFormat(CertificateFormat.PKCS12);
        this.ksInfo.setAlias("alias");
        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.UNSPECIFIED), Matchers.any(Date.class)))
                .thenThrow(new CredentialManagerInternalServiceException());
        Boolean result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(entityInfo, ksInfo, CrlReason.UNSPECIFIED);
            assertTrue(result);
            result = false; //reinit
            result = this.ifCertMngtMock.reIssueCertificate(entityInfo, ksInfo, CrlReason.UNSPECIFIED);// exception thrown second time cause of mockTheService method
            assertTrue(false);
        } catch (ReissueCertificateException e) {
            assertTrue(!result);
        } catch (EntityNotFoundException | InvalidCertificateFormatException | OtpNotValidException | OtpExpiredException e) {
            assertTrue(false);
        }
        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.AA_COMPROMISE), Matchers.any(Date.class)))
                .thenThrow(new CredentialManagerExpiredCertificateException());
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(entityInfo, ksInfo, CrlReason.A_A_COMPROMISE);
            assertTrue(false);
        } catch (ReissueCertificateException e) {
            assertTrue(!result);
        } catch (EntityNotFoundException | InvalidCertificateFormatException | OtpNotValidException | OtpExpiredException e) {
            assertTrue(false);
        }
        when(
                this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.AFFILIATION_CHANGED),
                        Matchers.any(Date.class))).thenThrow(new CredentialManagerAlreadyRevokedCertificateException());
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(entityInfo, ksInfo, CrlReason.AFFILIATION_CHANGED);
            assertTrue(false);
        } catch (ReissueCertificateException e) {
            assertTrue(!result);
        } catch (EntityNotFoundException | InvalidCertificateFormatException | OtpNotValidException | OtpExpiredException e) {
            assertTrue(false);
        }
        when(
                this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.CERTIFICATE_HOLD),
                        Matchers.any(Date.class))).thenThrow(new CredentialManagerCertificateNotFoundException());
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(entityInfo, ksInfo, CrlReason.CERTIFICATE_HOLD);
            assertTrue(result);
        } catch (ReissueCertificateException | EntityNotFoundException | InvalidCertificateFormatException | OtpNotValidException | OtpExpiredException e) {
            assertTrue(false);
        }
        //WARN: even if revoking in reissueCertificate returns false the caller method returns true
        when(
                this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.eq(CredentialManagerRevocationReason.CESSATION_OF_OPERATION),
                        Matchers.any(Date.class))).thenReturn(false);
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(entityInfo, ksInfo, CrlReason.CESSATION_OF_OPERATION);
            assertTrue(result);
        } catch (ReissueCertificateException | EntityNotFoundException | InvalidCertificateFormatException | OtpNotValidException | OtpExpiredException e) {
            assertTrue(false);
        }

        //CredMServiceWrapper Exception
        try {
            //First time called by issueCertforEnis, second time it triggers the exception
            when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.eq(true))).thenThrow(new IssueCertificateException());
        } catch (IssueCertificateException e) {
            System.out.println("Exception not expected mocking method");
        }
        result = false;
        try {
            result = this.ifCertMngtMock.reIssueCertificate(entityInfo, ksInfo, CrlReason.KEY_COMPROMISE);
            assertTrue(false);
        } catch (ReissueCertificateException e) {
            assertTrue(!result);
        } catch (EntityNotFoundException | InvalidCertificateFormatException | OtpNotValidException | OtpExpiredException e) {
            assertTrue(false);
        }
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmsapi.business.IfCertificateManagementImpl#issueCertificate(java.lang.String, com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType, java.lang.String, java.util.List, java.util.List, com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension)}
     * .
     */
    @Test
    public void testIssueCertificateFromCliForCli() {

        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            final String entityName = null;
            final String distinguishName = null;
            final SubjectAlternativeNameType subjectAltName = null;
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false, false, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("entityName is NULL or empty"));
        }

        final String entityName = "entityName";
        SubjectAlternativeNameType subjectAltName = null; // subjectAltName is not used

        try {
            final String distinguishName = null;
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false, false, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("entityProfileName is NULL or empty"));
        }

        String distinguishName = "distinguishName";

        try {
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false, false, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("distinguishName is not LDAP"));
        }

        distinguishName = "CN=distinguishName";

        try {
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false, false, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("entityProfileName is NULL or empty"));
        }

        final String entityProfileName = "entityProfileName";
        try {
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false, false, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("ksInfoList is NULL or empty"));
        }
        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();

        if (this.ksInfo.getKeyAndCertLocation() == null) {
            this.ksInfo.setKeyAndCertLocation("/tmp/keystore.p12");
        }
        if (this.ksInfo.getKeyStoreFolder() == null) {
            this.ksInfo.setKeyStoreFolder("");
        }
        if (this.ksInfo.getKeyStorePwd() == null) {
            this.ksInfo.setKeyStorePwd("keyStorePwd");
        }
        if (this.ksInfo.getCertFormat() == null) {
            this.ksInfo.setCertFormat(CertificateFormat.PKCS12);
        }

        ksInfoList.add(this.ksInfo);

        try {
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false, false, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("ksInfo not valid"));
        }

        if (this.ksInfo.getAlias() == null) {
            this.ksInfo.setAlias("myAlias");
        }

        // issueCertificateRESTchannel can't be called with valid parameters because of its infinite loop

        // partial tsInfo testcase
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();

        if (this.tsInfo.getTrustFileLocation() == null) {
            this.tsInfo.setTrustFileLocation("/tmp/truststore.jks");
        }
        if (this.tsInfo.getTrustFolder() == null) {
            this.tsInfo.setTrustFolder("");
        }
        if (this.tsInfo.getTrustStorePwd() == null) {
            this.tsInfo.setTrustStorePwd("trustStorePwd");
        }
        if (this.tsInfo.getCertFormat() == null) {
            this.tsInfo.setCertFormat(TrustFormat.JKS);
        }
        if (this.tsInfo.getTrustSource() == null) {
            this.tsInfo.setTrustSource(TrustSource.BOTH);
        }

        tsInfoList.add(this.tsInfo);

        try {
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false, false, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("tsInfo not valid"));
        }

        if (this.tsInfo.getAlias() == null) {
            this.tsInfo.setAlias("myAlias");
        }

        // partial crlInfo testcase
        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();

        if (this.crlInfo.getTrustFileLocation() == null) {
            this.crlInfo.setTrustFileLocation("/tmp/crlStore.crl");
        }
        if (this.crlInfo.getTrustStorePwd() == null) {
            this.crlInfo.setTrustStorePwd("crlStorePwd");
        }
        if (this.crlInfo.getCertFormat() == null) {
            this.crlInfo.setCertFormat(TrustFormat.BASE_64);
        }

        crlInfoList.add(this.crlInfo);

        try {
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false, true, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("crlInfo not valid"));
        }

        if (this.crlInfo.getAlias() == null) {
            this.crlInfo.setAlias("alias");
        }

        //
        // MOCKITO TEST
        //
        //        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        //        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/truststore.jks", "", TrustFormat.JKS, "", "alias", TrustSource.BOTH);
        //        tsInfoList.add(tsInfo);
        //
        //        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();
        //        final TrustStoreInfo crlInfo = new TrustStoreInfo("/tmp/crlTest.crl", "", TrustFormat.BASE_64, "", "Test", TrustSource.BOTH);
        //        crlInfoList.add(crlInfo);
        //
        subjectAltName = new SubjectAlternativeNameType();
        final List<String> listdirectoryname = new ArrayList<String>();
        listdirectoryname.add("dirname");
        subjectAltName.setDirectoryname(listdirectoryname);

        final Map<String, Attribute> attributes = new HashMap<String, Attribute>();
        final CredentialManagerCertificateExtension certificateExtensionInfo = new CredentialManagerCertificateExtensionImpl(attributes, "ipaddress=1.1.1.1");

        this.mockTheService();

        //////////////////////////////          
        //
        //        TEST CHECK
        //      
        //////////////////////////////

        boolean result = false;
        try {
            result = this.ifCertMngtMock.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo,
                    false, true, true);
        } catch (final Exception e) {
            assertTrue("Exception not expected: " + e.getMessage(), false);
        }
        assertTrue("issueCertificate", result);

        // delete the file
        File ksFile = new File("/tmp/keystore.p12");
        ksFile.delete();
        File tsFile = new File("/tmp/truststore.jks");
        tsFile.delete();
        File crlFile = new File("/tmp/crlStore.crl");
        crlFile.delete();
        //////////////////////////////          
        //
        //        TEST INSTALL
        //      
        //////////////////////////////   
        result = false;
        try {
            result = this.ifCertMngtMock.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo,
                    false, false, true);
        } catch (final Exception e) {
            assertTrue("Exception not expected: " + e.getMessage(), false);
        }
        assertTrue("issueCertificate", result);

        // delete the file
        ksFile = new File("/tmp/keystore.p12");
        ksFile.delete();
        tsFile = new File("/tmp/truststore.jks");
        tsFile.delete();
        crlFile = new File("/tmp/crlStore.crl");
        crlFile.delete();

        /*
         * Test fail on trust write
         */
        //TODO watch out for override entityname
        when(this.mockWrapper.getTrustCertificates("TOREndEntityProfile", CredentialManagerProfileType.ENTITY_PROFILE)).thenReturn(null);
        result = false;
        String entityExName = "entityNameTrustEx";
        String entityExProfileName = "TOREndEntityProfile";
        try {
            result = this.ifCertMngtMock.issueCertificateRESTchannel(entityExName, distinguishName, subjectAltName, entityExProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo,
                    false, false, true);
            assertTrue(result);
        } catch (final Exception e) {
            assertTrue(!result);
        }
        /*
         * Test fail on certificate generation
         */
        try {
            when(this.mockWrapper.getCertificate(Matchers.any(PKCS10CertificationRequest.class))).thenReturn(null);
        } catch (IssueCertificateException e1) {
            assertTrue("Exception not expected", false);
        }
        result = false;
        entityExName = "entityNameCertEx";
        try {
            result = this.ifCertMngtMock.issueCertificateRESTchannel(entityExName, distinguishName, subjectAltName, entityExProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo,
                    false, false, true);
            assertTrue(result);
        } catch (final Exception e) {
            assertTrue(!result);
        }
        // delete the file
        ksFile = new File("/tmp/keystore.p12");
        ksFile.delete();
        tsFile = new File("/tmp/truststore.jks");
        tsFile.delete();
        crlFile = new File("/tmp/crlStore.crl");
        crlFile.delete();

    }

    @Test
    public void testIssueCertificateFromCliForCliExc() {

        final String entityName = "entityName";
        String distinguishName = "CN=distinguishName";
        SubjectAlternativeNameType subjectAltName = null; // subjectAltName is not used
        final String entityProfileName = "entityProfileName";

        // ksInfo
        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        this.ksInfo.setKeyAndCertLocation("/tmp/keystore.p12");
        this.ksInfo.setKeyStoreFolder("");
        this.ksInfo.setKeyStorePwd("keyStorePwd");
        this.ksInfo.setCertFormat(CertificateFormat.PKCS12);
        this.ksInfo.setAlias("myAlias");
        ksInfoList.add(this.ksInfo);

        // tsInfo
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        this.tsInfo.setTrustFileLocation("/tmp/trust.jks");
        this.tsInfo.setTrustFolder("");
        this.tsInfo.setTrustStorePwd("trustStorePwd");
        this.tsInfo.setCertFormat(TrustFormat.JKS);
        this.tsInfo.setTrustSource(TrustSource.BOTH);
        this.tsInfo.setAlias("myAlias");
        tsInfoList.add(this.tsInfo);

        // crlInfo
        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();
        this.crlInfo.setTrustFileLocation("/tmp/crlStore.crl");
        this.crlInfo.setTrustStorePwd("crlStorePwd");
        this.crlInfo.setCertFormat(TrustFormat.BASE_64);
        this.crlInfo.setAlias("alias");
        crlInfoList.add(this.crlInfo);

        subjectAltName = new SubjectAlternativeNameType();
        final List<String> listdirectoryname = new ArrayList<String>();
        listdirectoryname.add("dirname");
        subjectAltName.setDirectoryname(listdirectoryname);

        final Map<String, Attribute> attributes = new HashMap<String, Attribute>();
        final CredentialManagerCertificateExtension certificateExtensionInfo = new CredentialManagerCertificateExtensionImpl(attributes, "ipaddress=1.1.1.1");

        boolean result = false;
        try {
            try {
                when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenReturn(this.mockWrapper);
            } catch (final Exception e) {
                assertTrue("Exception not expected: " + e.getMessage(), false);
            }

            when(mockWrapper.getProfile()).thenReturn(null);

            result = this.ifCertMngtMock.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo,
                    false, true, true);
            assertTrue("Exception expected", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception expected", true);
        }

        //prepare data for Profile
        final CredentialManagerProfileInfo mockProfile = PrepareCertificate.prepareProfileInfo();
        when(mockWrapper.getProfile()).thenReturn(mockProfile);

        try {
            when(mockWrapper.createAndGetEndEntity((Matchers.anyString()), Matchers.anyString())).thenReturn(null);

            result = this.ifCertMngtMock.issueCertificateRESTchannel(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo,
                    false, true, true);
            assertTrue("Exception expected", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("Entity is NULL"));
        }

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmsapi.business.IfCertificateManagementImpl#issueCertificate(java.lang.String, com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType, java.lang.String, java.util.List, java.util.List, com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension)}
     * .
     */
    @Test
    public void testIssueCertificateFromCli() {
        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            final String entityName = null;
            final String distinguishName = null;
            final SubjectAlternativeNameType subjectAltName = null;
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("entityName is NULL or empty"));
        }

        final String entityName = "entityName";
        SubjectAlternativeNameType subjectAltName = null;

        try {
            final String distinguishName = null;
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("entityProfileName is NULL or empty"));
        }

        String distinguishName = "distinguishName";
        try {
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("distinguishName is not LDAP"));
        }

        distinguishName = "CN=distinguishName";
        try {
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;
            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("entityProfileName is NULL or empty"));
        }

        final String entityProfileName = "entityProfileName";
        try {
            final List<KeystoreInfo> ksInfoList = null;
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("ksInfoList is NULL or empty"));
        }
        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();

        if (this.ksInfo.getKeyAndCertLocation() == null) {
            this.ksInfo.setKeyAndCertLocation("/tmp/keystore.jks");
        }
        if (this.ksInfo.getKeyStorePwd() == null) {
            this.ksInfo.setKeyStorePwd("keyStorePwd");
        }
        if (this.ksInfo.getCertFormat() == null) {
            this.ksInfo.setCertFormat(CertificateFormat.JKS);
        }

        ksInfoList.add(this.ksInfo);

        try {
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("ksInfo not valid"));
        }

        if (this.ksInfo.getAlias() == null) {
            this.ksInfo.setAlias("alias");
        }

        try {
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("could not resolve the JNDI name"));
        }

        subjectAltName = new SubjectAlternativeNameType();

        final List<String> listdirectoryname = new ArrayList<String>();
        listdirectoryname.add("dirname");
        subjectAltName.setDirectoryname(listdirectoryname);

        try {
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("could not resolve the JNDI name"));
        }

        /*
         * Final test case to test also a case of Chain flag set to true...
         */
        try {
            final List<TrustStoreInfo> tsInfoList = null;
            final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, true);
        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("could not resolve the JNDI name"));
        }

        //
        // MOCKITO TEST
        //
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/truststore.jks", "", TrustFormat.JKS, "", "alias", TrustSource.BOTH);
        tsInfoList.add(tsInfo);

        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo crlInfo = new TrustStoreInfo("/tmp/crlStore.crl", "", TrustFormat.BASE_64, "", "Test", TrustSource.BOTH);
        crlInfoList.add(crlInfo);

        final Map<String, Attribute> attributes = new HashMap<String, Attribute>();

        final CredentialManagerCertificateExtension certificateExtensionInfo = new CredentialManagerCertificateExtensionImpl(attributes, "ipaddress=1.1.1.1");

        this.mockTheService();

        //////////////////////////////          
        //
        //        TEST
        //      
        //////////////////////////////   
        boolean result = false;
        try {
            result = this.ifCertMngtMock.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, true);

        } catch (final Exception e) {
            assertTrue("Exception not expected: " + e.getMessage(), false);
        }
        assertTrue("issueCertificate", result);

        // delete the file
        File ksFile = new File("/tmp/keystore.jks");
        ksFile.delete();
        File tsFile = new File("/tmp/truststore.jks");
        tsFile.delete();
        File crlFile = new File("/tmp/crlStore.crl");
        crlFile.delete();

        /**
         * Test of non-existing entity (specific entity profile name - mocked)
         */

        try {
            result = this.ifCertMngtMock.issueCertificate("notExistingEntity", distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, true);

        } catch (final Exception e) {
            assertTrue("Exception not expected: " + e.getMessage(), false);
        }
        assertTrue("issueCertificate (not existing entity)", result);

        // delete the file
        ksFile = new File("/tmp/keystore.jks");
        ksFile.delete();
        tsFile = new File("/tmp/truststore.jks");
        tsFile.delete();
        crlFile = new File("/tmp/crlStore.crl");
        crlFile.delete();
    }

    @Test
    public void testIssueCertificateFromCliExc() {

        // ksInfo
        final String entityName = "entityName";
        final String distinguishName = "CN=distinguishName";
        final String entityProfileName = "entityProfileName";
        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        this.ksInfo.setKeyAndCertLocation("/tmp/keystore.jks");
        this.ksInfo.setKeyStorePwd("keyStorePwd");
        this.ksInfo.setCertFormat(CertificateFormat.JKS);
        this.ksInfo.setAlias("alias");
        ksInfoList.add(this.ksInfo);

        SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();

        final List<String> listdirectoryname = new ArrayList<String>();
        listdirectoryname.add("dirname");
        subjectAltName.setDirectoryname(listdirectoryname);

        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/truststore.jks", "", TrustFormat.JKS, "", "alias", TrustSource.BOTH);
        tsInfoList.add(tsInfo);

        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo crlInfo = new TrustStoreInfo("/tmp/crlStore.crl", "", TrustFormat.BASE_64, "", "Test", TrustSource.BOTH);
        crlInfoList.add(crlInfo);

        final Map<String, Attribute> attributes = new HashMap<String, Attribute>();

        final CredentialManagerCertificateExtension certificateExtensionInfo = new CredentialManagerCertificateExtensionImpl(attributes, "ipaddress=1.1.1.1");

        /**
         * Test of getProfile() returning null (exception)
         */
        try {
            try {
                when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenReturn(this.mockWrapper);
            } catch (final Exception e) {
                assertTrue("buildServiceWrapper failed", false);
            }

            //prepare data for Entity
            final CredentialManagerEntity mockEntityInfo = PrepareCertificate.prepareEntity();
            when(this.mockWrapper.getExistingEntity(Matchers.contains("entityName"))).thenReturn(mockEntityInfo);
            when(mockWrapper.getProfile(Matchers.anyString())).thenReturn(null);

            this.ifCertMngtMock.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, true);
            assertTrue("Exception expected", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("ProfileInfo is NULL"));
        }

        /**
         * Test of createAndGetEntity() returning null (exception)
         */
        //prepare data for Profile
        final CredentialManagerProfileInfo mockProfile = PrepareCertificate.prepareProfileInfo();
        when(mockWrapper.getProfile(Matchers.anyString())).thenReturn(mockProfile);

        try {
            when(mockWrapper.createAndGetEndEntity((Matchers.anyString()), Matchers.anyString())).thenReturn(null);

            this.ifCertMngtMock.issueCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, tsInfoList, crlInfoList, certificateExtensionInfo, true);
            assertTrue("Exception expected", false);
        } catch (IssueCertificateException e) {
            assertTrue("Exception expected", e.getMessage().contains("Entity is NULL"));
        }

    }

    @Test
    public void testCheckCertificate() {

        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            final String entityName = null;
            final String distinguishName = null;
            final SubjectAlternativeNameType subjectAltName = null;
            final String entityProfileName = null;
            final List<KeystoreInfo> ksInfoList = null;
            //final List<TrustStoreInfo> tsInfoList = null;
            //final List<TrustStoreInfo> crlInfoList = null;
            final CredentialManagerCertificateExtension certificateExtensionInfo = null;

            ifCertMngt.checkAndUpdateCertificate(entityName, distinguishName, subjectAltName, entityProfileName, ksInfoList, certificateExtensionInfo, false, true);

        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("entityName is NULL"));
        }

    }

    @Test
    public void testCheckCertificateMock() {

        final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();

        this.mockTheService();

        /**
         * Build Certificate
         */
        this.entityInfo.setEntityName("testentityname");
        this.entityInfo.setOneTimePassword("oneTimePassword");
        this.ksInfo.setKeyAndCertLocation("/tmp/keystore.p12");
        this.ksInfo.setKeyStorePwd("keyStorePwd");
        this.ksInfo.setCertFormat(CertificateFormat.PKCS12);
        this.ksInfo.setAlias("alias");

        boolean result = false;
        try {
            result = this.ifCertMngtMock.issueCertificate(this.entityInfo, this.ksInfo);
        } catch (final Exception e) {
            assertTrue("Exception during Certificate generation", false);
        }
        assertTrue("Certificate not generated", result);

        /**
         * Test execution
         */
        subjectAltName.getIpaddress().add(0, "1.1.1.1");

        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        ksInfoList.add(this.ksInfo);

        final CredentialManagerCertificateExtension certificateExtensionInfo = null;

        /**
         * Existing entity
         */
        String testEntityName = "entityName"; // as required by Mockito
        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "DN=distinguishName", subjectAltName, "entityProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue("Check Certificate failed", result);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception during Certificate check", false);
        }

        this.ksInfo.delete();

        /**
         * Non-existing entity
         */
        testEntityName = "notExistingEntity"; // as required by Mockito

        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "DN=distinguishName", subjectAltName, "entityProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue("Check Certificate failed", result);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception during Certificate check", false);
        }

        this.ksInfo.delete();

        /**
         * GetExistingEntity internal error
         */
        testEntityName = "internalErrorEntity"; // as required by Mockito

        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "DN=distinguishName", subjectAltName, "entityProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue("Exception not occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception expected", true);
        }
        /**
         * Test generate certificate exceptions
         */
        //IssueCertificateException
        result = false;
        try {
            when(this.mockWrapper.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.eq("entityNameIssueEx"), Matchers.anyBoolean(), Matchers.anyString())).thenThrow(
                    new IssueCertificateException());
        } catch (IssueCertificateException | OtpExpiredException | OtpNotValidException e1) {
            assertTrue("Exception not expected", false);
        }
        testEntityName = "entityNameIssueEx";
        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "DN=distinguishName", null, "entityProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }
        //OtpExpiredException
        try {
            when(this.mockWrapper.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.eq("entityNameOtpExpExc"), Matchers.anyBoolean(), Matchers.anyString())).thenThrow(
                    new OtpExpiredException());
        } catch (IssueCertificateException | OtpExpiredException | OtpNotValidException e1) {
            assertTrue("Exception not expected", false);
        }
        testEntityName = "entityNameOtpExpExc";
        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "DN=distinguishName", null, "entityProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }
        //OtpNotValidException
        try {
            when(this.mockWrapper.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.eq("entityNameOtpInvEx"), Matchers.anyBoolean(), Matchers.anyString())).thenThrow(
                    new OtpNotValidException());
        } catch (IssueCertificateException | OtpExpiredException | OtpNotValidException e1) {
            assertTrue("Exception not expected", false);
        }
        testEntityName = "entityNameOtpInvEx";
        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "DN=distinguishName", null, "entityProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }

        /**
         * Test certificate entity to reissue
         */
        CredentialManagerEntity reissueEntity = PrepareCertificate.prepareEntity();
        reissueEntity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        reissueEntity.setName("reissueEntityName");
        testEntityName = reissueEntity.getName();
        when(this.mockWrapper.getExistingEntity(Matchers.eq("reissueEntityName"))).thenThrow(new CredentialManagerEntityNotFoundException());
        try {
            when(
                    this.mockWrapper.createAndGetEntity(Matchers.eq("reissueEntityName"), Matchers.any(CredentialManagerSubject.class), Matchers.any(CredentialManagerSubjectAltName.class),
                            Matchers.any(CredentialManagerAlgorithm.class), Matchers.anyString())).thenReturn(reissueEntity);
        } catch (IssueCertificateException e1) {
            assertTrue(false);
        }
        CredentialManagerProfileInfo reissueProfileInfo = PrepareCertificate.prepareProfileInfo();
        CredentialManagerSubject reissueSubject = new CredentialManagerSubject();
        reissueSubject.setCommonName("CN");
        reissueProfileInfo.setSubjectByProfile(reissueSubject);
        when(this.mockWrapper.getProfile("reissueProfileName")).thenReturn(reissueProfileInfo);
        KeyPair certKP = PrepareCertificate.createKeyPair();
        X509Certificate cert = PrepareCertificate.prepareCertificate(certKP);
        X509Certificate[] certArray = { cert };
        KeystoreInfo keyInfo = new KeystoreInfo("/tmp/certReissue.jks", "", "", "", CertificateFormat.JKS, "keyStorePwd", "alias");
        CredentialWriter jksCert = new JKSWriter(keyInfo.getKeyStoreFolder(), keyInfo.getKeyAndCertLocation(), keyInfo.getKeyStorePwd(), keyInfo.getCertFormat().name());
        try {
            jksCert.storeKeyPair(certKP.getPrivate(), certArray, keyInfo.getAlias());
        } catch (StorageException e1) {
            System.out.println("Unexpected exception");
        }
        ksInfoList.clear();
        ksInfoList.add(keyInfo);
        when(this.mockWrapper.getMode()).thenReturn(channelMode.REST_CHANNEL);
        //first time to emulate the fact that the certificate is valid and all is well
        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "CN=CN", null, "reissueProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue(!result);
        } catch (final IssueCertificateException e) {
            assertTrue(result);
        }
        //second time to emulate the fact that the certificate has to be revoked (successfully)
        reissueEntity.setEntityStatus(CredentialManagerEntityStatus.REISSUE);
        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "CN=CN", null, "reissueProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }
        //second time to emulate that the revoke went bad
        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class))).thenReturn(false);
        try {
            result = this.ifCertMngtMock.checkAndUpdateCertificate(testEntityName, "CN=CN", null, "reissueProfileName", ksInfoList, certificateExtensionInfo, false, true);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }
        File keyReissueStore = new File(keyInfo.getKeyAndCertLocation());
        keyReissueStore.delete();
        keyInfo.delete();

        /**
         * Test failed crl/trust write
         */

        TrustStoreInfo trustLockInfo = new TrustStoreInfo("/tmp/trustInstallLock.jks", "", TrustFormat.JKS, "trustStorePwd", "alias_pippo", TrustSource.INTERNAL);
        List<TrustStoreInfo> trustLockList = new ArrayList<TrustStoreInfo>();
        trustLockList.add(trustLockInfo);
        result = false;
        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo crlInfo = new TrustStoreInfo("/tmp/crlStore.crl", "", TrustFormat.BASE_64, "", "Test", TrustSource.BOTH);
        crlInfoList.add(crlInfo);
        List<KeystoreInfo> ksInfoLockList = new ArrayList<KeystoreInfo>();
        ksInfoLockList.add(this.ksInfo);
        when(this.mockWrapper.getExistingEntity(Matchers.eq("trustLockEntity"))).thenThrow(new CredentialManagerEntityNotFoundException());
        //fail on retrieve crl
        try {
            when(this.mockWrapper.getCRLs("TOREndEntityProfile", CredentialManagerProfileType.ENTITY_PROFILE)).thenThrow(new IssueCertificateException());
        } catch (IssueCertificateException e3) {
            assertTrue(false);
        }
        try {
            result = this.ifCertMngtMock.issueCertificate("trustLockEntity", "CN=CN", null, "entityProfileName", ksInfoLockList, trustLockList, crlInfoList, null, false);
            assertTrue(result);
        } catch (IssueCertificateException e2) {
            assertTrue(!result);
        }
        //fail on retrieve trusts
        when(this.mockWrapper.getTrustCertificates("TOREndEntityProfile", CredentialManagerProfileType.ENTITY_PROFILE)).thenReturn(null);
        try {
            result = this.ifCertMngtMock.issueCertificate("trustLockEntity", "CN=CN", null, "TOREndEntityProfile", ksInfoLockList, trustLockList, crlInfoList, null, false);
            assertTrue(result);
        } catch (IssueCertificateException e2) {
            assertTrue(!result);
        }
        trustLockInfo.delete();
        this.ksInfo.delete();
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmsapi.business.IfCertificateManagementImpl#reIssueCertificate(com.ericsson.oss.itpf.security.credmsapi.api.model.UserInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)}
     * .
     */
    @Test
    public void testReIssueCertificate() {
        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            final CrlReason revocationReason = null;
            ifCertMngt.reIssueCertificate(this.entityInfo, this.ksInfo, revocationReason);
            assertTrue("Exception expected", false);
        } catch (final ReissueCertificateException e) {
            assertTrue(true);
        } catch (final Exception e) {
            assertTrue("Exception not expected", false);
        }
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmsapi.business.IfCertificateManagementImpl#revokeCertificate(com.ericsson.oss.itpf.security.credmsapi.api.model.UserInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)}
     * .
     */

    @Test
    public void testRevokeCertificateEntityNull() {

        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            final CrlReason revocationReason = null;
            ifCertMngt.revokeCertificate(null, revocationReason);
            assertTrue("Exception not occurred", false);
        } catch (final RevokeCertificateException | EntityNotFoundException e) {
            assertTrue("Exception occurred", e.getMessage().contains("EntityInfo not valid"));
        }
        // fail("Not yet implemented");
    }

    @Test
    public void testRevokeCertificateEntityNameNull() {
        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            ifCertMngt.revokeCertificate(this.entityInfo, null);
            assertTrue("Exception not occurred", false);
        } catch (final RevokeCertificateException | EntityNotFoundException e) {
            assertTrue("Exception occurred", e.getMessage().contains("EntityInfo not valid"));
        }
    }

    @Test
    public void testRevokeCertificateEntityNameEmpty() {

        this.entityInfo.setEntityName("");

        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            ifCertMngt.revokeCertificate(this.entityInfo, null);
            assertTrue("Exception not occurred", false);
        } catch (final RevokeCertificateException | EntityNotFoundException e) {
            assertTrue("Exception occurred", e.getMessage().contains("EntityInfo not valid"));
        }
    }

    @Test
    public void testRevokeCertificateReasonNull() {

        this.entityInfo.setEntityName("entityName");

        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            ifCertMngt.revokeCertificate(this.entityInfo, null);
            assertTrue("Exception not occurred", false);
        } catch (final RevokeCertificateException | EntityNotFoundException e) {
            assertTrue("Exception occurred", e.getMessage().contains("RevocationReason not valid: it cannot be null"));
        }
    }

    @Test
    public void testRevokeCertificateBuildWrapperExc() {

        this.entityInfo.setEntityName("entityName");

        try {
            when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenThrow(new IssueCertificateException());

            this.ifCertMngtMock.revokeCertificate(this.entityInfo, CrlReason.A_A_COMPROMISE);
            assertTrue("Exception not occurred", false);
        } catch (final RevokeCertificateException e) {
            assertTrue("Exception occurred", e.getMessage().contains("buildServiceWrapper failed"));
        } catch (final IssueCertificateException e) {
            assertTrue("Unexpected Exception occurred", false);
        } catch (final EntityNotFoundException e) {
            assertTrue("Unexpected Exception occurred", false);
        }
    }

    @Test
    public void testRevokeCertificateExc() {

        this.entityInfo.setEntityName("entityName");

        try {
            when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenReturn(this.mockWrapper);

            Mockito.doThrow(new RevokeCertificateException("mock-generated")).when(this.mockWrapper)
                    .revokeCertificateByEntity(Matchers.anyString(), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));

            this.ifCertMngtMock.revokeCertificate(this.entityInfo, CrlReason.A_A_COMPROMISE);
            assertTrue("Exception not occurred", false);
        } catch (final RevokeCertificateException e) {
            assertTrue("Exception occurred", !e.getMessage().contains("buildServiceWrapper"));
        } catch (final EntityNotFoundException e) {
            assertTrue("Unexpected Exception occurred", false);
        } catch (final Exception e) {
            assertTrue("Internal Exception occurred", false);
        }

        try {
            when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenReturn(this.mockWrapper);

            Mockito.doThrow(new EntityNotFoundException("mock-generated")).when(this.mockWrapper)
                    .revokeCertificateByEntity(Matchers.anyString(), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));

            this.ifCertMngtMock.revokeCertificate(this.entityInfo, CrlReason.AFFILIATION_CHANGED);
            assertTrue("Exception not occurred", false);
        } catch (final RevokeCertificateException e) {
            assertTrue("Unexpected Exception occurred", false);
        } catch (final EntityNotFoundException e) {
            assertTrue("Exception occurred", !e.getMessage().contains("buildServiceWrapper"));
        } catch (final Exception e) {
            assertTrue("Internal Exception occurred", false);
        }
    }

    @Test
    public void testRevokeCertificateSuccess() {

        this.entityInfo.setEntityName("entityName");

        try {
            when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenReturn(this.mockWrapper);

            // isOTPValid
            // when(this.mockWrapper.isOTPValid(Matchers.anyString(), Matchers.anyString())).thenReturn(true);

            Mockito.doNothing().when(this.mockWrapper).revokeCertificateByEntity(Matchers.anyString(), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));

            this.ifCertMngtMock.revokeCertificate(this.entityInfo, CrlReason.A_A_COMPROMISE);
            assertTrue("Exception not occurred", true);
        } catch (final RevokeCertificateException e) {
            assertTrue("Exception occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Unexpected Exception occurred", false);
        } catch (final Exception e) {
            assertTrue("Internal Exception occurred", false);
        }
    }

    @Test
    public void testCheckCRL() {
        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        try {
            final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();
            final List<String> listdirectoryname = new ArrayList<String>();
            listdirectoryname.add("dirname");
            subjectAltName.setDirectoryname(listdirectoryname);
            final List<TrustStoreInfo> crlListInfo = new ArrayList<TrustStoreInfo>();
            crlListInfo.add(this.crlInfo);
            ifCertMngt.checkAndUpdateCRL("entityName", crlListInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue(true);
        }
        // fail("Not yet implemented");
    }

    @Test
    public void testCheckCrlMock() {

        this.mockTheService();

        this.crlInfo.setTrustFileLocation("/tmp/testCrlstore.pem");
        this.crlInfo.setCertFormat(TrustFormat.BASE_64); // Only BASE_64 allowed
        this.crlInfo.setTrustSource(TrustSource.BOTH);

        /**
         * Remove existing crl file (if any)
         */
        final File file = new File(this.crlInfo.getTrustFileLocation());
        if (file.exists()) {
            file.delete();
        }

        /**
         * Test: no crl file (build expected)
         */
        String testEntityName = "entityName"; // as required by mock

        final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();
        final List<String> listdirectoryname = new ArrayList<String>();
        listdirectoryname.add("dirname");
        subjectAltName.setDirectoryname(listdirectoryname);
        final List<TrustStoreInfo> crlListInfo = new ArrayList<TrustStoreInfo>();
        crlListInfo.add(this.crlInfo);

        try {
            this.ifCertMngtMock.checkAndUpdateCRL(testEntityName, crlListInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue("checkAndUpdateCRL failed", false);
        }

        assertTrue("Crl file not stored", (file.length() > 0));

        /**
         * Test (check existing CRL)
         */
        testEntityName = "entityName"; // as required by mock

        try {
            this.ifCertMngtMock.checkAndUpdateCRL(testEntityName, crlListInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue("checkAndUpdateCRL failed", false);
        }

        this.crlInfo.delete(); // remove CRL

        /**
         * Test (generate exception)
         */
        this.crlInfo.setTrustFileLocation(null);

        try {
            this.ifCertMngtMock.checkAndUpdateCRL(testEntityName, crlListInfo, false);
            assertTrue("checkAndUpdateCRL: exception not occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("checkAndUpdateCRL: exception occurred", true);
        }

        /**
         * Test (TrustProfile)
         */
        final String testProfileName = "profileName"; // as required by mock
        this.crlInfo.setTrustFileLocation("/tmp/testCrlstore.pem");

        try {
            this.ifCertMngtMock.checkAndUpdateCRL_TP(testProfileName, crlListInfo, false);
        } catch (final IssueCertificateException e) {
            assertTrue("checkAndUpdateCRL_TP failed", false);
        }

        this.crlInfo.delete(); // remove CRL

        /**
         * Test cannot delete crl
         */

        File lockDir = new File("/tmp/locktestCheckCrlMockDir");
        lockDir.mkdir();
        X509CRL lock1Crl = PrepareCertificate.generateInternalCrl().getInternalCACrlMap().get("pippo").retrieveCRL();
        this.crlInfo.setTrustFileLocation(lockDir.getAbsolutePath() + "/testCrlStorageException.pem");
        CredentialWriter lock64Crl = null;
        try {
            lock64Crl = new Base64Writer(this.crlInfo.getTrustFolder(), this.crlInfo.getTrustFileLocation(), "", "", this.crlInfo.getTrustStorePwd());
            lock64Crl.addCrlEntry(lock1Crl, this.crlInfo.getAlias());
        } catch (StorageException e2) {
            assertTrue(false);
        }
        File lock64CrlRef = new File(this.crlInfo.getTrustFileLocation()); //should be a reference to the crl file
        assertTrue(lock64CrlRef.setReadable(true, true) && lock64CrlRef.setWritable(false, true) && lock64CrlRef.setExecutable(false, true));
        assertTrue(lockDir.setReadable(true, true) && lockDir.setWritable(false, true) && lockDir.setExecutable(true, true));

        when(this.mockWrapper.compareCRLsAndRetrieve(Matchers.anyString(), Matchers.any(CredentialManagerProfileType.class), Matchers.any(SortedSet.class), Matchers.any(TrustSource.class)))
                .thenReturn(PrepareCertificate.generateCrl());

        boolean result = false;
        try {
            result = this.ifCertMngtMock.checkAndUpdateCRL_TP(testProfileName, crlListInfo, false);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }
        this.crlInfo.delete();
        assertTrue(lockDir.setReadable(true, false) && lockDir.setWritable(true, false) && lockDir.setExecutable(true, false));
        assertTrue(lock64CrlRef.setReadable(true, false) && lock64CrlRef.setWritable(true, false) && lock64CrlRef.setExecutable(true, false));
        assertTrue(lock64CrlRef.delete());
        assertTrue(lockDir.delete());

        /**
         * Test Crl forceUpdate true
         */
        this.crlInfo.setTrustFileLocation("/tmp/testCrlstoreForce.pem");
        this.crlInfo.setAlias("alias");

        result = false;
        try {
            when(this.mockWrapper.getCRLs(Matchers.anyString(), Matchers.any(CredentialManagerProfileType.class))).thenReturn(null);
        } catch (final Exception e1) {
            assertTrue("checkAndUpdateCRL_TP failed", false);
        }
        try {
            result = this.ifCertMngtMock.checkAndUpdateCRL_TP(testProfileName, crlListInfo, true);
            assertTrue(!result);
        } catch (final IssueCertificateException e) {
            assertTrue(result);
        }
        this.crlInfo.delete(); // remove CRL

        /**
         * Test Crl wrong storage type
         */
        this.crlInfo.setTrustFileLocation("/tmp/testCrlstoreWrongStorage.jks");
        this.crlInfo.setCertFormat(TrustFormat.JKS);
        result = false;
        try {
            result = this.ifCertMngtMock.checkAndUpdateCRL_TP(testProfileName, crlListInfo, false);
            assertTrue(!result);
        } catch (final IssueCertificateException e) {
            assertTrue(result);
        }
        this.crlInfo.delete();

        /**
         * Test expired crl
         */
        try {
            when(this.mockWrapper.getCRLs(Matchers.anyString(), Matchers.any(CredentialManagerProfileType.class))).thenReturn(PrepareCertificate.generateCrl());
        } catch (IssueCertificateException e2) {
            assertTrue("checkAndUpdateCRL_TP failed", false);
        }
        X509CRL intCrl = PrepareCertificate.generateExpiredInternalCrl().getInternalCACrlMap().get("pippo").retrieveCRL();
        this.crlInfo.setTrustFileLocation("/tmp/testCrlExpired.pem");
        this.crlInfo.setCertFormat(TrustFormat.BASE_64);
        this.crlInfo.setAlias("pippo");
        CredentialWriter base64Crl = null;
        try {
            base64Crl = new Base64Writer(this.crlInfo.getTrustFolder(), this.crlInfo.getTrustFileLocation(), "", "", this.crlInfo.getTrustStorePwd());
            base64Crl.addCrlEntry(intCrl, this.crlInfo.getAlias());
        } catch (StorageException e1) {
            System.out.println("Unexpected exception");
        }

        result = false;
        try {
            result = this.ifCertMngtMock.checkAndUpdateCRL_TP(testProfileName, crlListInfo, false);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }
        this.crlInfo.delete();
        File fileCrlExpired = new File(this.crlInfo.getTrustFileLocation());
        fileCrlExpired.delete();

        /**
         * Test get crl issueCertificate exception
         */

        try {
            when(this.mockWrapper.getCRLs(Matchers.anyString(), Matchers.any(CredentialManagerProfileType.class))).thenThrow(new IssueCertificateException());
        } catch (IssueCertificateException e2) {
            assertTrue("checkAndUpdateCRL_TP failed", false);
        }
        this.crlInfo.setTrustFileLocation("/tmp/testCrlIssueCertificateException.pem");
        result = false;
        try {
            result = this.ifCertMngtMock.checkAndUpdateCRL_TP(testProfileName, crlListInfo, false);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }

    }

    @Test
    public void testGetCredentialManagerInterfaceVersion() {
        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        final String result = ifCertMngt.getCredentialManagerInterfaceVersion();
        assertNotNull(result);

    }

    /////////////////////////////////////////////////////
    @Test
    public void testGetEndEntitiesByCategory() {
        final String testCat = "Category1";
        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        List<EntitySummary> entities = new ArrayList<EntitySummary>();
        try {
            entities = ifCertMngt.getEndEntitiesByCategory(testCat);
        } catch (final GetEndEntitiesByCategoryException e) {
            assertNotNull(entities);
        } catch (final InvalidCategoryNameException e) {
            assertNotNull(entities);
        }
        // fail("Not yet implemented");
    }

    @Test
    public void testGetEndEntitiesByCategoryMock() {

        this.mockTheService();

        List<EntitySummary> listOfEntities = null;

        try {
            listOfEntities = this.ifCertMngtMock.getEndEntitiesByCategory("wrongCategory");
            assertTrue("Exception not occurred", false);
        } catch (GetEndEntitiesByCategoryException | InvalidCategoryNameException e) {
            assertTrue("Exception expected", true);
        }

        try {
            listOfEntities = this.ifCertMngtMock.getEndEntitiesByCategory("realCategory");
            assertTrue("List of entities not generated", listOfEntities.get(0).getName() == "realEntity");
        } catch (GetEndEntitiesByCategoryException | InvalidCategoryNameException e) {
            assertTrue("Exception not expected", false);
        }

        try {
            listOfEntities = this.ifCertMngtMock.getEndEntitiesByCategory("emptyCategory");
            assertTrue("List of entities not empty", listOfEntities.isEmpty());
        } catch (GetEndEntitiesByCategoryException | InvalidCategoryNameException e) {
            assertTrue("Exception not expected", false);
        }

        try {
            listOfEntities = this.ifCertMngtMock.getEndEntitiesByCategory("exceptionCategory");
            assertTrue("Exception not occurred", false);
        } catch (final GetEndEntitiesByCategoryException e) {
            assertTrue("Exception expected", true);
        } catch (final InvalidCategoryNameException e) {
            assertTrue("Exception not expected", false);
        }

        try {
            listOfEntities = this.ifCertMngtMock.getEndEntitiesByCategory("notFoundCategory");
            assertTrue("Exception not occurred", false);
        } catch (final GetEndEntitiesByCategoryException e) {
            assertTrue("Exception not expected", false);
        } catch (final InvalidCategoryNameException e) {
            assertTrue("Exception expected", true);
        }
    }

    //@Ignore
    @Test
    public void testCheckTrustsMock() {

        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        boolean result = false;
        //first run
        String entityName = null;
        SubjectAlternativeNameType altName = null;
        String entityProfileName = null;

        List<TrustStoreInfo> tsInfoList = null;
        final boolean isOwn = false;

        tsInfoList = new ArrayList<TrustStoreInfo>();
        //        this.tsInfo.setTrustFileLocation(null);
        //        this.tsInfo.setCertFormat(TrustFormat.PKCS12);
        //        tsInfoList.add(this.tsInfo);

        /**
         * Test (exception)
         */
        entityName = "testentityname";
        entityProfileName = "entityProfileName";

        this.tsInfo = new TrustStoreInfo("/tmp/truststore.p12", null, TrustFormat.PKCS12, "trustStorePwd", "alias", TrustSource.BOTH);
        tsInfoList.clear();
        tsInfoList.add(this.tsInfo);

        altName = new SubjectAlternativeNameType();

        final List<String> listdirectoryname = new ArrayList<String>();
        listdirectoryname.add("dirname");
        altName.setDirectoryname(listdirectoryname);

        try {
            ifCertMngt.checkAndUpdateTrusts(entityName, entityProfileName, tsInfoList, isOwn);

        } catch (final IssueCertificateException e) {
            assertTrue(e.getMessage().contains("could not resolve the JNDI name"));
        }

        this.mockTheService();

        /**
         * Testcase: already existing trustStore
         */

        try {
            result = this.ifCertMngtMock.checkAndUpdateTrusts(entityName, entityProfileName, tsInfoList, isOwn);
            assertTrue("checkAndUpdateTrusts passed", result);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception not expected", false);
        }

        /**
         * Testcase: not existing trustStore
         */

        this.tsInfo.delete(); // remove any existing file
        //
        //        if (this.tsInfo.getAlias() == null) {
        //            this.tsInfo.setAlias("alias");
        //        }

        final File file = new File(this.tsInfo.getTrustFileLocation());

        try {
            result = this.ifCertMngtMock.checkAndUpdateTrusts(entityName, entityProfileName, tsInfoList, isOwn);
            assertTrue("checkAndUpdateTrusts failed", result && (file.length() > 0));
        } catch (final IssueCertificateException e) {
            assertTrue("Exception not expected", false);
        }

        /**
         * Testcase: trustStore only
         */

        try {
            result = this.ifCertMngtMock.checkAndUpdateTrustsTP("trustProfileName", tsInfoList);
            assertTrue("checkAndUpdateTrustsTP passed", result);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception not expected", false);
        }

        try {
            result = this.ifCertMngtMock.checkAndUpdateTrustsTP("trustProfileName", new ArrayList<TrustStoreInfo>());
            assertTrue("checkAndUpdateTrustsTP without trusts", !result);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception not expected", false);
        }
        this.tsInfo.delete(); // remove any existing file

        /**
         * Testcase: trustStore expired
         */

        tsInfoList.clear();
        X509Certificate trust = PrepareCertificate.prepareExpiredCertificate(PrepareCertificate.createKeyPair());
        TrustStoreInfo trustInfo = new TrustStoreInfo("/tmp/trustExpired.jks", "", TrustFormat.JKS, "trustStorePwd", "alias", TrustSource.INTERNAL);
        CredentialWriter jksTrust = null;
        try {
            jksTrust = new JKSWriter(trustInfo.getTrustFolder(), trustInfo.getTrustFileLocation(), trustInfo.getTrustStorePwd(), trustInfo.getCertFormat().name());
            jksTrust.addTrustedEntry(trust, trustInfo.getAlias());
        } catch (StorageException e1) {
            System.out.println("Unexpected exception");
        }

        tsInfoList.add(trustInfo);
        try {
            result = this.ifCertMngtMock.checkAndUpdateTrustsTP("trustProfileName", tsInfoList);
            assertTrue("checkAndUpdateTrustsTP expired trusts", result);
            trustInfo.delete();
        } catch (final IssueCertificateException e) {
            assertTrue("Exception not expected", false);
        }
        File fileTrustExpired = new File("/tmp/trustExpired.jks");
        fileTrustExpired.delete();

        /**
         * Testcase: CredentialManagerReaderInstance fail
         */
        tsInfoList.clear();
        trustInfo = new TrustStoreInfo(null, null, TrustFormat.BASE_64, null, null, null);
        tsInfoList.add(trustInfo);
        result = false;
        try {
            result = this.ifCertMngtMock.checkAndUpdateTrustsTP("trustProfileName", tsInfoList);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
            trustInfo.delete();
        }

        /**
         * Testcase: cannot rewrite trust
         */
        File lockDir = new File("/tmp/lockedDir");
        lockDir.mkdir();
        tsInfoList.clear();
        X509Certificate trustNoWrite = PrepareCertificate.prepareCertificate(PrepareCertificate.createKeyPair());
        trustInfo = new TrustStoreInfo("/tmp/lockedDir/trustNotWrite.jks", "", TrustFormat.JKS, "trustStorePwd", "alias", TrustSource.INTERNAL);
        jksTrust = new JKSWriter(trustInfo.getTrustFolder(), trustInfo.getTrustFileLocation(), trustInfo.getTrustStorePwd(), trustInfo.getCertFormat().name());
        try {
            jksTrust.addTrustedEntry(trustNoWrite, trustInfo.getAlias());
        } catch (StorageException e1) {
            System.out.println("Unexpected exception");
        }
        tsInfoList.add(trustInfo);
        result = false;
        try {
            Runtime.getRuntime().exec("chmod 400 " + trustInfo.getTrustFileLocation());
            Runtime.getRuntime().exec("chmod 500 " + lockDir.getAbsolutePath());
        } catch (IOException e1) {
            assertTrue(false);
        }
        try {
            result = this.ifCertMngtMock.checkAndUpdateTrustsTP("trustProfileName", tsInfoList);
            assertTrue(result);
        } catch (final IssueCertificateException e) {
            assertTrue(!result);
        }
        try {
            Runtime.getRuntime().exec("chmod 744 " + lockDir.getAbsolutePath());
            Runtime.getRuntime().exec("rm " + trustInfo.getTrustFileLocation());
            Runtime.getRuntime().exec("rm -r " + lockDir.getAbsolutePath());
        } catch (IOException e1) {
            assertTrue(false);
        }

        /**
         * Testcase: return null from getTrustCertificates (trust file not existent)
         */
        tsInfoList.clear();
        trustInfo = new TrustStoreInfo("/tmp/trustValid.jks", "", TrustFormat.JKS, "trustStorePwd", "alias", TrustSource.INTERNAL);
        tsInfoList.add(trustInfo);
        result = false;
        when(this.mockWrapper.getTrustCertificates(Matchers.eq("trustProfileName"), Matchers.eq(CredentialManagerProfileType.TRUST_PROFILE))).thenReturn(null);
        try {
            result = this.ifCertMngtMock.checkAndUpdateTrustsTP("trustProfileName", tsInfoList);
            assertTrue("checkAndUpdateTrustsTP passed (no update)", !result);
            trustInfo.delete();
        } catch (final IssueCertificateException e) {
            assertTrue("Exception not expected", false);
        }

        tsInfoList.clear();

        this.tsInfo.delete(); // remove any existing file

    }

    ///////////////////////////////////////////////////////////////
    ////////////////// GetCertificatesByEntityName ////////////////
    ///////////////////////////////////////////////////////////////

    @Test
    public void testGetCertificatesByEntityName() {

        final String entityName = "entityNotExixting";
        final EntityType entityType = EntityType.ENTITY;
        final CertificateStatus certStatus = CertificateStatus.ACTIVE;
        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        List<CertificateSummary> certSummaryList = new ArrayList<CertificateSummary>();

        try {
            certSummaryList = ifCertMngt.getCertificatesByEntityName(entityName, entityType, certStatus);
        } catch (final CertificateNotFoundException e) {
            assertNotNull(certSummaryList);
        } catch (final GetCertificatesByEntityNameException e) {
            assertNotNull(certSummaryList);
        } catch (final EntityNotFoundException e) {
            assertNotNull(certSummaryList);
        }

    }

    @Test
    public void testGetCertificatesByEntityNameMock() {

        this.mockTheService();

        List<CertificateSummary> certSummaryList = null;

        //// first check
        try {
            certSummaryList = this.ifCertMngtMock.getCertificatesByEntityName("realEntity", EntityType.ENTITY, CertificateStatus.ACTIVE);
            assertTrue("List of certificates summary not generated", certSummaryList.get(0).getIssuerDN().equals("CN=issuerFirst"));
        } catch (CertificateNotFoundException | GetCertificatesByEntityNameException | EntityNotFoundException e) {
            assertTrue("Exception not expected", false);
        }

        //// second check
        try {
            certSummaryList = this.ifCertMngtMock.getCertificatesByEntityName("GenericEx", EntityType.ENTITY, CertificateStatus.ACTIVE);
            assertTrue("Exception not occurred", false);
        } catch (final GetCertificatesByEntityNameException e) {
            assertTrue("Generic Exception expected", true);
        } catch (final CertificateNotFoundException e) {
            assertTrue("Exception not expected", false);
        } catch (final EntityNotFoundException e) {
            assertTrue("Exception not expected", false);
        }

        //// third check
        try {
            certSummaryList = this.ifCertMngtMock.getCertificatesByEntityName("CertNotFoundEx", EntityType.ENTITY, CertificateStatus.ACTIVE);
            assertTrue("Exception not occurred", false);
        } catch (final GetCertificatesByEntityNameException e) {
            assertTrue("Exception not expected", false);
        } catch (final CertificateNotFoundException e) {
            assertTrue("Certfificate Not Found Exception expected", true);
        } catch (final EntityNotFoundException e) {
            assertTrue("Exception not expected", false);
        }

        //// fourth check
        try {
            certSummaryList = this.ifCertMngtMock.getCertificatesByEntityName("EntNotFoundEx", EntityType.ENTITY, CertificateStatus.ACTIVE);
            assertTrue("Exception not occurred", false);
        } catch (final GetCertificatesByEntityNameException e) {
            assertTrue("Exception not expected", false);
        } catch (final CertificateNotFoundException e) {
            assertTrue("Exception not expected", false);
        } catch (final EntityNotFoundException e) {
            assertTrue("Entity Not Found Exception expected", true);
        }

    }

    //////////////////////////////////////////////////////////////
    ////////////////// revokeEntityCertificate //////////////////
    /////////////////////////////////////////////////////////////

    @Test
    public void testRevokeEntityCertificate() {

        Boolean result = new Boolean(false);
        final IfCertificateManagementImpl ifCertMngt = new IfCertificateManagementImpl();
        String issuerDN = "CN=AnyIssuer";
        String subjectDN = "CN=AnySubject";
        String certificateSN = "123456789";
        CrlReason revocationReason = CrlReason.UNSPECIFIED;
        try {
            result = ifCertMngt.revokeEntityCertificate(issuerDN, subjectDN, certificateSN, revocationReason);
            assertTrue("An exception is expected", false);
        } catch (final CertificateNotFoundException e) {
            assertTrue("result is not false", result == false);
        } catch (ExpiredCertificateException e) {
            assertTrue("result is not false", result == false);
        } catch (AlreadyRevokedCertificateException e) {
            assertTrue("result is not false", result == false);
        } catch (RevokeEntityCertificateException e) {
            assertTrue("result is not false", result == false);
        }

    }

    @Test
    public void testRevokeEntityCertificateMock() {

        final Boolean revokeResult = true;
        final X500Principal issuerDn = new X500Principal("CN=issuerAny");
        final BigInteger serialNum = new BigInteger("123456789");

        //// first check
        final X500Principal subjectDnFirstCheck = new X500Principal("CN=subjectOK");
        final CredentialManagerCertificateIdentifier credManCertIdFirstCheck = new CredentialManagerCertificateIdentifier(subjectDnFirstCheck, issuerDn, serialNum);

        //// second check
        final X500Principal subjectDnSecondCheck = new X500Principal("CN=subjectInternalException");
        final CredentialManagerCertificateIdentifier credManCertIdSecondCheck = new CredentialManagerCertificateIdentifier(subjectDnSecondCheck, issuerDn, serialNum);

        //// third check
        final X500Principal subjectDnThirdCheck = new X500Principal("CN=subjectCertNotFoundException");
        final CredentialManagerCertificateIdentifier credManCertIdthirdCheck = new CredentialManagerCertificateIdentifier(subjectDnThirdCheck, issuerDn, serialNum);

        //// fourth check
        final X500Principal subjectDnFourthCheck = new X500Principal("CN=subjectCertExpiredException");
        final CredentialManagerCertificateIdentifier credManCertIdFourthCheck = new CredentialManagerCertificateIdentifier(subjectDnFourthCheck, issuerDn, serialNum);

        //// fifth check
        final X500Principal subjectDnFifthCheck = new X500Principal("CN=subjectCertAlreadyRevokedException");
        final CredentialManagerCertificateIdentifier credManCertIdFifthCheck = new CredentialManagerCertificateIdentifier(subjectDnFifthCheck, issuerDn, serialNum);

        // mock the wrapperFactory in order to return the mocked wrapper
        try {
            when(this.mockWrapperFactory.buildServiceWrapper(Matchers.any(CredMServiceWrapper.channelMode.class), Matchers.anyBoolean())).thenReturn(this.mockWrapper);
        } catch (final Exception e1) {
            e1.printStackTrace();
        }

        try {
            //// first check
            when(this.mockWrapper.revokeCertificateById(Matchers.eq(credManCertIdFirstCheck), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class)))
                    .thenReturn(revokeResult);

            //// second check
            when(this.mockWrapper.revokeCertificateById(Matchers.eq(credManCertIdSecondCheck), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class))).thenThrow(
                    new CredentialManagerInternalServiceException());

            //// third check
            when(this.mockWrapper.revokeCertificateById(Matchers.eq(credManCertIdthirdCheck), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class))).thenThrow(
                    new CredentialManagerCertificateNotFoundException());

            //// fourth check
            when(this.mockWrapper.revokeCertificateById(Matchers.eq(credManCertIdFourthCheck), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class))).thenThrow(
                    new CredentialManagerExpiredCertificateException());

            //// fifth check
            when(this.mockWrapper.revokeCertificateById(Matchers.eq(credManCertIdFifthCheck), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class))).thenThrow(
                    new CredentialManagerAlreadyRevokedCertificateException());

        } catch (final CredentialManagerInternalServiceException | CredentialManagerCertificateNotFoundException | CredentialManagerExpiredCertificateException
                | CredentialManagerAlreadyRevokedCertificateException e) {
            e.printStackTrace();
        }

        //// first check
        try {
            Boolean revokeResultCheck = this.ifCertMngtMock.revokeEntityCertificate("CN=issuerAny", "CN=subjectOK", "123456789", CrlReason.UNSPECIFIED);
            assertTrue("revokeResultCheck is not true", revokeResultCheck == true);
        } catch (final CertificateNotFoundException | ExpiredCertificateException | AlreadyRevokedCertificateException | RevokeEntityCertificateException e) {
            assertTrue("Exceptions not expected", false);
        }

        //// second check
        try {
            this.ifCertMngtMock.revokeEntityCertificate("CN=issuerAny", "CN=subjectInternalException", "123456789", CrlReason.UNSPECIFIED);
            assertTrue("RevokeEntityCertificateException Exception expected", false);
        } catch (CertificateNotFoundException e) {
            assertTrue("RevokeEntityCertificateException Exception expected", false);
        } catch (ExpiredCertificateException e) {
            assertTrue("RevokeEntityCertificateException Exception expected", false);
        } catch (AlreadyRevokedCertificateException e) {
            assertTrue("RevokeEntityCertificateException Exception expected", false);
        } catch (RevokeEntityCertificateException e) {
            assertTrue("RevokeEntityCertificateException Exception expected", true);
        }

        //// third check
        try {
            this.ifCertMngtMock.revokeEntityCertificate("CN=issuerAny", "CN=subjectCertNotFoundException", "123456789", CrlReason.UNSPECIFIED);
            assertTrue("CertificateNotFoundException Exception expected", false);
        } catch (CertificateNotFoundException e) {
            assertTrue("CertificateNotFoundException Exception expected", true);
        } catch (ExpiredCertificateException e) {
            assertTrue("CertificateNotFoundException Exception expected", false);
        } catch (AlreadyRevokedCertificateException e) {
            assertTrue("CertificateNotFoundException Exception expected", false);
        } catch (RevokeEntityCertificateException e) {
            assertTrue("CertificateNotFoundException Exception expected", false);
        }

        //// fourth check
        try {
            this.ifCertMngtMock.revokeEntityCertificate("CN=issuerAny", "CN=subjectCertExpiredException", "123456789", CrlReason.UNSPECIFIED);
            assertTrue("ExpiredCertificateException Exception expected", false);
        } catch (CertificateNotFoundException e) {
            assertTrue("ExpiredCertificateException Exception expected", false);
        } catch (ExpiredCertificateException e) {
            assertTrue("ExpiredCertificateException Exception expected", true);
        } catch (AlreadyRevokedCertificateException e) {
            assertTrue("ExpiredCertificateException Exception expected", false);
        } catch (RevokeEntityCertificateException e) {
            assertTrue("ExpiredCertificateException Exception expected", false);
        }

        //// fifth check
        try {
            this.ifCertMngtMock.revokeEntityCertificate("CN=issuerAny", "CN=subjectCertAlreadyRevokedException", "123456789", CrlReason.UNSPECIFIED);
            assertTrue("AlreadyRevokedCertificateException Exception expected", false);
        } catch (CertificateNotFoundException e) {
            assertTrue("AlreadyRevokedCertificateException Exception expected", false);
        } catch (ExpiredCertificateException e) {
            assertTrue("AlreadyRevokedCertificateException Exception expected", false);
        } catch (AlreadyRevokedCertificateException e) {
            assertTrue("AlreadyRevokedCertificateException Exception expected", true);
        } catch (RevokeEntityCertificateException e) {
            assertTrue("AlreadyRevokedCertificateException Exception expected", false);
        }

    }

    @Test
    public void revokeEntityCertificateWrongParameters() throws CertificateNotFoundException, ExpiredCertificateException, AlreadyRevokedCertificateException {
        Boolean result = false;
        String issuerDN = null;
        String subjectDN = null;
        String serialNumber = null;
        CrlReason reason = null;
        for (int i = 0; i <= 7; i++) {
            switch (i) {
            case 1:
                issuerDN = "";
                break;
            case 2:
                issuerDN = "issuer";
                break; //intentionally not a correct DN
            case 3:
                subjectDN = "";
                break;
            case 4:
                subjectDN = "CN=subject";
                break;
            case 5:
                serialNumber = "";
                break;
            case 6:
                serialNumber = "ab234f";
                break;
            case 7:
                reason = CrlReason.UNSPECIFIED;
            }
            try {
                result = this.ifCertMngtMock.revokeEntityCertificate(issuerDN, subjectDN, serialNumber, reason);
                assertTrue(result);
            } catch (RevokeEntityCertificateException e) {
                assertTrue(!result);
            }
        }
    }

    @Test
    public void testCheckXMLInputFail() throws IssueCertificateException, EntityNotFoundException, InvalidCertificateFormatException, OtpNotValidException, OtpExpiredException {
        boolean result = false;
        String entityName = null;
        String entityProfileName = null;
        String dN = null;
        SubjectAlternativeNameType subj = null;
        List<KeystoreInfo> ksCheckList = new ArrayList<KeystoreInfo>();
        KeystoreInfo ksCheck = new KeystoreInfo("/tmp/checkKS.jks", "", "", "", CertificateFormat.JKS, "kspwd", "alias");
        List<TrustStoreInfo> tsCheckList = new ArrayList<TrustStoreInfo>();
        List<TrustStoreInfo> crlCheckList = new ArrayList<TrustStoreInfo>();
        when(this.mockWrapperFactory.buildServiceWrapper(CredMServiceWrapper.channelMode.REST_CHANNEL, false)).thenThrow(new IssueCertificateException());

        for (int i = 0; i < 5; i++) {
            switch (i) {
            case 0:
                entityName = "";
                break;
            case 1:
                entityName = "fakeEN";
                entityProfileName = "";
                break;
            case 2: //keystore empty
                entityProfileName = "fakeEPN";
                break;
            case 3: //truststore and crlstore empty
                ksCheckList.add(ksCheck);
                break;
            }
            try {
                result = this.ifCertMngtMock.issueCertificateRESTchannel(entityName, dN, subj, entityProfileName, ksCheckList, tsCheckList, crlCheckList, null, false, false, false);
                assertTrue(result);
            } catch (IssueCertificateException e) {
                assertTrue(!result);
            }
        }
    }

    @Test
    public void testIssueCertFromEnisCheckInputFail() throws EntityNotFoundException, InvalidCertificateFormatException, OtpNotValidException, OtpExpiredException {
        KeystoreInfo failKI = null;
        EntityInfo failEI = null;
        boolean result = false;
        for (int i = 0; i < 6; i++) {
            switch (i) {//do nothing on i=0
            case 1:
                failEI = new EntityInfo();
                failEI.setEntityName("entityName");
                failEI.setOneTimePassword("otp");
                break;
            case 2:
                failKI = new KeystoreInfo("", "", "", "", CertificateFormat.PKCS12, "pawd", null);
                break;
            case 3:
                failKI.setKeyAndCertLocation("/tmp/lockedFolder/cert.p12");
                break;
            case 4:
                failKI.setKeyAndCertLocation("/tmp/kscheck.p12");
                break;
            case 5:
                failKI.setAlias("");
                break;
            default:
                //do nothing
            }
            try {
                result = this.ifCertMngtMock.issueCertificate(failEI, failKI);
                assertTrue(result);
            } catch (IssueCertificateException e) {
                assertTrue(!result);
            }
        }
    }
}
