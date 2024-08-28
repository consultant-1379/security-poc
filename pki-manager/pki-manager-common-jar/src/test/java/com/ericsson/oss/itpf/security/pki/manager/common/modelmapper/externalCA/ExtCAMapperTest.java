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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.cert.CRLException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;

@RunWith(MockitoJUnitRunner.class)
public class ExtCAMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityMapper.class);

    @InjectMocks
    ExtCAMapper extCAMapper;

    CAEntityData extCAData;
    CAEntityData extCADataWithSubjectEMailAddress;
    ExtCA extCA;


    @Before
    public void setup() throws IOException, CRLException {
        fillExtCA();
        fillExtCAWithSubjectEMailAddress();
        fillExtCAData();
    }

    @Test
    public void testToAPIModel() throws Exception {

        final ExtCA extCATest = extCAMapper.toAPIFromModel(extCAData);
        assertEquals("MyExtCA", extCATest.getCertificateAuthority().getName());
        assertEquals(true, extCATest.getCertificateAuthority().isRootCA());
        assertEquals("Despicable", extCATest.getCertificateAuthority().getSubject().getSubjectFields().get(0).getValue());
        assertEquals(SubjectFieldType.COMMON_NAME, extCATest.getCertificateAuthority().getSubject().getSubjectFields().get(0).getType());

    }

    @Test
    public void testToAPIModelWithSubjectEMAILADDRESS() throws Exception {

        final ExtCA extCATest = extCAMapper.toAPIFromModel(extCADataWithSubjectEMailAddress);
        assertEquals("MyExtCA", extCATest.getCertificateAuthority().getName());
        assertEquals(true, extCATest.getCertificateAuthority().isRootCA());
        assertNotNull(extCATest.getCertificateAuthority().getSubject());

    }

    private void fillExtCAData() throws IOException, CRLException {
        extCAData = new CAEntityData();

        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("MyExtCA");
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setSubjectDN("CN=Despicable");
        extCAData.setCertificateAuthorityData(certificateAuthorityData);
        extCAData.setExternalCA(true);
    }

    private void fillExtCAWithSubjectEMailAddress() throws IOException, CRLException {
        extCADataWithSubjectEMailAddress = new CAEntityData();

        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("MyExtCA");
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setSubjectDN("CN=Despicable, EMAILADDRESS=pippo@pluto.com");
        extCADataWithSubjectEMailAddress.setCertificateAuthorityData(certificateAuthorityData);
        extCADataWithSubjectEMailAddress.setExternalCA(true);
    }
    /**
     *
     */
    private void fillExtCA() {
        extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("MyExtCA");
        certificateAuthority.setRootCA(true);

        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList();
        final SubjectField subjectField1 = new SubjectField();
        subjectField1.setType(SubjectFieldType.COMMON_NAME);
        subjectField1.setValue("Despicable");
        subjectFields.add(subjectField1);
        final SubjectField subjectField2 = new SubjectField();
        subjectField2.setType(SubjectFieldType.STREET_ADDRESS);
        subjectField2.setValue("Via Vesuvio");
        subjectFields.add(subjectField2);
        subject.setSubjectFields(subjectFields);
        certificateAuthority.setSubject(subject);

        extCA.setCertificateAuthority(certificateAuthority);

    }

}
