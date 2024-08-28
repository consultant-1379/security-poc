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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.parser;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;

@RunWith(MockitoJUnitRunner.class)
public class CertificateGenerationInfoParserTest extends BaseTest {

    @InjectMocks
    private CertificateGenerationInfoParser certificateGenerationInfoParser;

    private CertificateGenerationInfo certificateInfo;
    private CertificateAuthority certificateAuthority;
    private CertificateAuthority issuerCA;
    private EntityInfo entityInfo;
    private String issuerDN;
    private String subjectDN;
    private SubjectAltName subjectAltName;

    /**
     * Prepares initial data.
     */
    @Before
    public void setUp() {
    }

    /**
     * Method to test getting of issuerDN from {@link CertificateGenerationInfo} for RootCA.
     */
    @Test
    public void testGetIssuerDNFromCertGenerationInfoForRootCA() {
        prepareCertificateGenerationInfoForRootCA();

        issuerDN = certificateGenerationInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo);

        assertNotNull(issuerDN);
        assertEquals(certificateInfo.getCAEntityInfo().getSubject().toASN1String(), issuerDN);
    }

    /**
     * Method to test getting of issuerDN from {@link CertificateGenerationInfo} for SubCA.
     */
    @Test
    public void testGetIssuerDNFromCertGenerationInfoForSubCA_WithActiveCertForRootCA() {
        prepareCertificateGenerationInfoForSubCA();

        issuerDN = certificateGenerationInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo);

        assertNotNull(issuerDN);
        assertEquals(certificateInfo.getIssuerCA().getActiveCertificate().getSubject().toASN1String(), issuerDN);
    }

    /**
     * Method to test getting of issuerDN from {@link CertificateGenerationInfo} for SubCA.
     */
    @Test
    public void testGetIssuerDNFromCertGenerationInfoForSubCA() {
        prepareCertificateGenerationInfoForSubCA();

        issuerDN = certificateGenerationInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo);

        assertNotNull(issuerDN);
        assertEquals(certificateInfo.getIssuerCA().getSubject().toASN1String(), issuerDN);
    }

    /**
     * Method to test getting of subjectDN from {@link CertificateGenerationInfo} for Entity.
     */
    @Test
    public void testGetSubjectDNFromCertGenerationInfoForCA() {
        prepareCertificateGenerationInfoForRootCA();

        subjectDN = certificateGenerationInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo);

        assertNotNull(subjectDN);
        assertEquals(certificateInfo.getCAEntityInfo().getSubject().toASN1String(), subjectDN);
    }

    /**
     * Method to test getting of subjectDN from {@link CertificateGenerationInfo} for Entity.
     */
    @Test
    public void testGetSubjectDNFromCertGenerationInfoForEntity() {
        prepareCertificateGenerationInfoForEntity();

        subjectDN = certificateGenerationInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo);

        assertNotNull(subjectDN);
        assertEquals(certificateInfo.getEntityInfo().getSubject().toASN1String(), subjectDN);
    }

    /**
     * Method to test getting of subjectAltName from {@link CertificateGenerationInfo} for Entity.
     */
    @Test
    public void testGetSubjectAltNameFromCertGenerationInfoForCA() {
        prepareCertificateGenerationInfoForRootCA();

        subjectAltName = certificateGenerationInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateInfo);

        assertNotNull(subjectAltName);
        assertEquals(certificateInfo.getCAEntityInfo().getSubjectAltName(), subjectAltName);
    }

    /**
     * Method to test getting of subjectAltName from {@link CertificateGenerationInfo} for Entity.
     */
    @Test
    public void testGetSubjectAltNameFromCertGenerationInfoForEntity() {
        prepareCertificateGenerationInfoForEntity();

        subjectAltName = certificateGenerationInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateInfo);

        assertNotNull(subjectAltName);
        assertEquals(certificateInfo.getEntityInfo().getSubjectAltName(), subjectAltName);
    }

    private void prepareCertificateGenerationInfoForRootCA() {
        certificateInfo = new CertificateGenerationInfo();

        certificateAuthority = prepareCAData(true);
        certificateInfo.setCAEntityInfo(certificateAuthority);
    }

    private void prepareCertificateGenerationInfoForSubCA() {

        certificateInfo = new CertificateGenerationInfo();

        Certificate activeCertificate = new Certificate();
        Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        final SubjectField common_name = new SubjectField();
        common_name.setType(SubjectFieldType.COMMON_NAME);
        common_name.setValue("ERBS_node");

        final SubjectField organization = new SubjectField();
        organization.setType(SubjectFieldType.ORGANIZATION);
        organization.setValue("ENM");

        final SubjectField organization_unit = new SubjectField();
        organization_unit.setType(SubjectFieldType.ORGANIZATION_UNIT);
        organization_unit.setValue("Ericsson");

        subjectFields.add(common_name);
        subjectFields.add(organization);
        subjectFields.add(organization_unit);

        subject.setSubjectFields(subjectFields);
        activeCertificate.setSubject(subject);
        issuerCA = prepareCAData(false);
        if (activeCertificate != null) {
            issuerCA.setActiveCertificate(activeCertificate);
        }
        certificateInfo.setIssuerCA(issuerCA);

    }

    private void prepareCertificateGenerationInfoForEntity() {
        certificateInfo = new CertificateGenerationInfo();

        entityInfo = prepareEntityInfo();
        certificateInfo.setEntityInfo(entityInfo);
    }
}
