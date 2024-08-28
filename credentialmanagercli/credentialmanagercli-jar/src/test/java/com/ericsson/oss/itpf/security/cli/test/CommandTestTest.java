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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command.COMMAND_TYPE;
import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.CommandTest;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaExternalServiceApiWrapperFactory;
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
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateSummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntitySummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.Subject;

@RunWith(MockitoJUnitRunner.class)
public class CommandTestTest {

    //////////////////////////////////////////////////////
    @InjectMocks
    // (answer=Answers.CALLS_REAL_METHODS)
    CommandTest mockedCommandTest;
    @Mock
    CredMaExternalServiceApiWrapperFactory mockWrapperFactory;
    @Mock
    CredMaExternalServiceApiWrapper mockWrapper;

    ///////////////////////////////////////////////////////////////////////

    @Test
    public void test1() {

        final CommandTest test = new CommandTest();
        test.setArguments("empty=test");

        final int result = test.execute();
        assertTrue("test.execute", result == 0);

        final COMMAND_TYPE result2 = test.getType();
        assertTrue("test.getType", result2.equals(COMMAND_TYPE.TEST));

        final List<String> result3 = test.getValidArguments();
        assertFalse("test.getValidArguments", result3.isEmpty());
        assertTrue("test.getValidArguments", result3.get(0).contains("-t"));
    }

    private void prepareWrapper() {

        // mock the wrapperFactory in order to return the mocked wrapper
        try {
            lenient().when(this.mockWrapperFactory.getInstance(Matchers.anyString())).thenReturn(this.mockWrapper);
        } catch (final Exception e1) {
            e1.printStackTrace();
        }

    }

    private void mockIt() {

        this.prepareWrapper();

        final List<EntitySummary> entityList = new ArrayList<EntitySummary>();
        try {
            when(this.mockWrapper.getEndEntitiesByCategory(Matchers.anyString())).thenReturn(entityList);
        } catch (final Exception e) {
            e.printStackTrace();
        }

        final Boolean issueOk = new Boolean(true);
        try {
            when(this.mockWrapper.issueCertificateForENIS(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class))).thenReturn(issueOk);
        } catch (final Exception e) {
            e.printStackTrace();
        }

        final Boolean reIssueok = new Boolean(true);
        try {
            when(this.mockWrapper.reIssueCertificate(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class), Matchers.any(CrlReason.class))).thenReturn(reIssueok);
        } catch (final Exception e) {
            e.printStackTrace();
        }

        final Boolean revokeOk = new Boolean(true);
        try {
            when(this.mockWrapper.revokeCertificate(Matchers.any(EntityInfo.class), Matchers.any(CrlReason.class))).thenReturn(revokeOk);
        } catch (final Exception e) {
            e.printStackTrace();
        }

        final List<CertificateSummary> certificateList = new ArrayList<CertificateSummary>();
        CertificateSummary certificateSummary = new CertificateSummary("CN=issuercN", "CN=cn", "0483ae89b1", CertificateStatus.ACTIVE);
        certificateList.add(certificateSummary);
        try {
            when(this.mockWrapper.getCertificatesByEntityName(Matchers.anyString(), Matchers.any(EntityType.class), Matchers.any(CertificateStatus.class))).thenReturn(certificateList);
        } catch (final Exception e) {
            e.printStackTrace();
        }

        final Boolean revokeEntityCertificateOk = new Boolean(true);
        try {
            when(this.mockWrapper.revokeEntityCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenReturn(revokeEntityCertificateOk);
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final Boolean reIssueLegacyXMLCertOk = new Boolean(true);
        try {
            when(this.mockWrapper.reIssueLegacyXMLCertificate(Matchers.any(EntityInfo.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenReturn(reIssueLegacyXMLCertOk);
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void test2() {

        this.mockedCommandTest.setArguments("getEntityByCategory=SERVICE");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test2a() {

        this.mockedCommandTest.setArguments("getEntityByCategory=SEC-GW");
        this.prepareWrapper();

        final List<EntitySummary> entityList = new ArrayList<EntitySummary>();
        EntitySummary esum1 = new EntitySummary("entityName", EntityStatus.INACTIVE, new Subject());
        entityList.add(esum1);
        try {
            when(this.mockWrapper.getEndEntitiesByCategory("SEC-GW")).thenReturn(entityList);
        } catch (final Exception e) {
            e.printStackTrace();
        }

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);

    }

    @Test
    public void test3() {

        this.mockedCommandTest.setArguments("issueCertificateForENIS=ATCLVM500centos+/tmp/enis01.jks+enisPwd+enis01+JKS");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test4() {

        this.mockedCommandTest.setArguments("reIssueCertificate=ATCLVM500centos+/tmp/enis02.p12+enisPwd+enis02+PKCS12+CA_COMPROMISE");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test5() {

        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM500centos+SUPERSEDED");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test6() {

        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM500centos+A_A_COMPROMISE");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test7() {

        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM500centos+AFFILIATION_CHANGED");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test8() {

        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM500centos+CERTIFICATE_HOLD");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test9() {

        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM500centos+CESSATION_OF_OPERATION");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test10() {

        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM500centos+KEY_COMPROMISE");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test11() {

        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM500centos+PRIVILEGE_WITHDRAWN");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test12() {

        this.mockedCommandTest.setArguments("reIssueCertificate=ATCLVM500centos+/tmp/enis012.jceks+enisPwd+enis012+JCEKS+REMOVE_FROM_CRL");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test13() {

        this.mockedCommandTest.setArguments("reIssueCertificate=ATCLVM500centos+/tmp/enis013.pem+enisPwd+enis013+BASE_64+UNSPECIFIED");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

    @Test
    public void test14() {
        this.mockedCommandTest.setArguments("getCertificatesByEntityName=ATCLVM500centos+entity+ACTIVE");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void test15() {
        this.mockedCommandTest
                .setArguments("revokeEntityCertificate=OU=BUCI_DUAC_NAM,C=SE,O=ERICSSON,CN=ENM_Management_CA+O=ERICSSON,OU=BUCI_DUAC_NAM,C=SE,CN=ATCLVM500centos+1216774470808261868+UNSPECIFIED");
        this.mockIt();

        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void test16() {
    this.mockedCommandTest
                .setArguments("reIssueLegacyXMLCertificate=ATCLVM500centos+/tmp/enis016.xml+pwdLocation+UNSPECIFIED");
    this.mockIt();
    
    final int result = this.mockedCommandTest.execute();
    assertTrue("test.execute", result == 0);
    }

    //exceptions

    @Test
    public void testEx1() {
        this.mockedCommandTest.setArguments("getEntityByCategory=SERVICE");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.getEndEntitiesByCategory(Matchers.anyString())).thenThrow(new GetEndEntitiesByCategoryException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx2() {
        this.mockedCommandTest.setArguments("getEntityByCategory=NODE-OAM");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.getEndEntitiesByCategory(Matchers.anyString())).thenThrow(new InvalidCategoryNameException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx3() {
        this.mockedCommandTest.setArguments("issueCertificateForENIS=ATCLVM500centos+/tmp/enis01.jks+enisPwd+enis01+JKS");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.issueCertificateForENIS(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class))).thenThrow(new IssueCertificateException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx4() {
        this.mockedCommandTest.setArguments("issueCertificateForENIS=ATCLVM500centos+/tmp/enis01.jks+enisPwd+enis01+JKS");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.issueCertificateForENIS(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class))).thenThrow(new EntityNotFoundException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx5() {
        this.mockedCommandTest.setArguments("issueCertificateForENIS=ATCLVM500centos+/tmp/enis01.jks+enisPwd+enis01+JKS");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.issueCertificateForENIS(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class))).thenThrow(new InvalidCertificateFormatException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx6() {
        this.mockedCommandTest.setArguments("issueCertificateForENIS=ATCLVM500centos+/tmp/enis01.jks+enisPwd+enis01+JKS");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.issueCertificateForENIS(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class))).thenThrow(new OtpNotValidException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx7() {
        this.mockedCommandTest.setArguments("issueCertificateForENIS=ATCLVM500centos+/tmp/enis01.p12+enisPwd+enis01+PKCS12");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.issueCertificateForENIS(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class))).thenThrow(new OtpExpiredException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx8() {
        this.mockedCommandTest.setArguments("getCertificatesByEntityName=ATCLVM500centos+ENTITY+ACTIVE");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.getCertificatesByEntityName(Matchers.anyString(), Matchers.any(EntityType.class), Matchers.any(CertificateStatus.class))).thenThrow(
                    new CertificateNotFoundException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx9() {
        this.mockedCommandTest.setArguments("getCertificatesByEntityName=ATCLVM500centos+ENTITY+EXPIRED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.getCertificatesByEntityName(Matchers.anyString(), Matchers.any(EntityType.class), Matchers.any(CertificateStatus.class))).thenThrow(new EntityNotFoundException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx10() {
        this.mockedCommandTest.setArguments("getCertificatesByEntityName=ATCLVM500centos+ENTITY+REVOKED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.getCertificatesByEntityName(Matchers.anyString(), Matchers.any(EntityType.class), Matchers.any(CertificateStatus.class))).thenThrow(
                    new GetCertificatesByEntityNameException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx11() {
        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM500centos+SUPERSEDED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.revokeCertificate(Matchers.any(EntityInfo.class), Matchers.any(CrlReason.class))).thenThrow(new RevokeCertificateException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx12() {
        this.mockedCommandTest.setArguments("revokeCertificate=ATCLVM503centos+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.revokeCertificate(Matchers.any(EntityInfo.class), Matchers.any(CrlReason.class))).thenThrow(new EntityNotFoundException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx13() {
        this.mockedCommandTest.setArguments("reIssueCertificate=ATCLVM500centos+/tmp/enis03.p12+enisPwd+enis02+PKCS12+CA_COMPROMISE");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueCertificate(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class), Matchers.any(CrlReason.class))).thenThrow(new ReissueCertificateException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx14() {
        this.mockedCommandTest.setArguments("reIssueCertificate=ATCLVM500centos+/tmp/enis03.p12+enisPwd+enis02+PKCS12+CA_COMPROMISE");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueCertificate(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class), Matchers.any(CrlReason.class))).thenThrow(new EntityNotFoundException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx15() {
        this.mockedCommandTest.setArguments("reIssueCertificate=ATCLVM500centos+/tmp/enis03.p12+enisPwd+enis02+PKCS12+CA_COMPROMISE");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueCertificate(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class), Matchers.any(CrlReason.class))).thenThrow(
                    new InvalidCertificateFormatException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx16() {
        this.mockedCommandTest.setArguments("reIssueCertificate=ATCLVM500centos+/tmp/enis03.p12+enisPwd+enis02+PKCS12+CA_COMPROMISE");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueCertificate(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class), Matchers.any(CrlReason.class))).thenThrow(new OtpNotValidException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }

    @Test
    public void testEx17() {
        this.mockedCommandTest.setArguments("reIssueCertificate=ATCLVM500centos+/tmp/enis03.p12+enisPwd+enis02+PKCS12+CA_COMPROMISE");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueCertificate(Matchers.any(EntityInfo.class), Matchers.any(KeystoreInfo.class), Matchers.any(CrlReason.class))).thenThrow(new OtpExpiredException());
        } catch (Exception e) {
            e.printStackTrace();
        }

        int result = this.mockedCommandTest.execute();
        assertTrue(result == 0);
    }
    
    @Test
    public void testEx18() {
        this.mockedCommandTest
                .setArguments("revokeEntityCertificate=OU=BUCI_DUAC_NAM,C=SE,O=ERICSSON,CN=ENM_Management_CA+O=ERICSSON,OU=BUCI_DUAC_NAM,C=SE,CN=ATCLVM500centos+1216774470808261868+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.revokeEntityCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenThrow(new CertificateNotFoundException());
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void testEx19() {
        this.mockedCommandTest
                .setArguments("revokeEntityCertificate=OU=BUCI_DUAC_NAM,C=SE,O=ERICSSON,CN=ENM_Management_CA+O=ERICSSON,OU=BUCI_DUAC_NAM,C=SE,CN=ATCLVM500centos+1216774470808261868+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.revokeEntityCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenThrow(new ExpiredCertificateException());
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void testEx20() {
        this.mockedCommandTest
                .setArguments("revokeEntityCertificate=OU=BUCI_DUAC_NAM,C=SE,O=ERICSSON,CN=ENM_Management_CA+O=ERICSSON,OU=BUCI_DUAC_NAM,C=SE,CN=ATCLVM500centos+1216774470808261868+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.revokeEntityCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenThrow(new AlreadyRevokedCertificateException());
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void testEx21() {
        this.mockedCommandTest
                .setArguments("revokeEntityCertificate=OU=BUCI_DUAC_NAM,C=SE,O=ERICSSON,CN=ENM_Management_CA+O=ERICSSON,OU=BUCI_DUAC_NAM,C=SE,CN=ATCLVM500centos+1216774470808261868+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.revokeEntityCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenThrow(new RevokeEntityCertificateException());
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void testEx22() {
        this.mockedCommandTest
                   .setArguments("reIssueLegacyXMLCertificate=ATCLVM500centos+/tmp/enis022Ex.xml+pwdLocation+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueLegacyXMLCertificate(Matchers.any(EntityInfo.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenThrow(new EntityNotFoundException());
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void testEx23() {
        this.mockedCommandTest
                   .setArguments("reIssueLegacyXMLCertificate=ATCLVM500centos+/tmp/enis023Ex.xml+pwdLocation+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueLegacyXMLCertificate(Matchers.any(EntityInfo.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenThrow(new OtpNotValidException());
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void testEx24() {
        this.mockedCommandTest
                   .setArguments("reIssueLegacyXMLCertificate=ATCLVM500centos+/tmp/enis024Ex.xml+pwdLocation+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueLegacyXMLCertificate(Matchers.any(EntityInfo.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenThrow(new OtpExpiredException());
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }
    
    @Test
    public void testEx25() {
        this.mockedCommandTest
                   .setArguments("reIssueLegacyXMLCertificate=ATCLVM500centos+/tmp/enis025Ex.xml+pwdLocation+UNSPECIFIED");
        this.prepareWrapper();

        try {
            when(this.mockWrapper.reIssueLegacyXMLCertificate(Matchers.any(EntityInfo.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString(), Matchers.any(CrlReason.class))).thenThrow(new ReIssueLegacyXMLCertificateException());
        } catch (final Exception e) {
            e.printStackTrace();
        }
        
        final int result = this.mockedCommandTest.execute();
        assertTrue("test.execute", result == 0);
    }

} // end of file

