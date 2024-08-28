package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;

@RunWith(MockitoJUnitRunner.class)
public class CertificateUtilTest {

    @InjectMocks
    CertificateUtil certificateUtil;

    @Test
    public void testGetEntityType() {

        final int pathLengthConstarint = 0;

        certificateUtil.getEntityType(pathLengthConstarint);

    }

    @Test
    public void testGetEntityType_Entity() {

        final int pathLengthConstarint = -1;

        certificateUtil.getEntityType(pathLengthConstarint);

    }

    @Test
    public void testGetKeyUsage_KeyUsagesNull() {

        final boolean[] keyUsages = null;

        certificateUtil.getKeyUsage(keyUsages);

    }

    @Test
    public void testGetKeyUsage() {

        boolean[] keyUsages = new boolean[2];
        keyUsages[1] = true;
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        final KeyUsageType keyUsageType = KeyUsageType.CRL_SIGN;
        keyUsageTypes.add(keyUsageType);

        certificateUtil.getKeyUsage(keyUsages);

    }

    @Test
    public void testGetSubjectAltName_SubjectAltNameFieldsEmpty() {

        final SubjectAltName subjectAltName = new SubjectAltName();

        certificateUtil.getSubjectAltName(subjectAltName);

    }

    @Test
    public void testGetSubjectAltName_EDIPARTYNAME() {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        final EdiPartyName ediPartyName = new EdiPartyName();
        ediPartyName.setNameAssigner("ROOT");
        subjectAltNameField.setValue(ediPartyName);
        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        certificateUtil.getSubjectAltName(subjectAltName);

    }

    @Test
    public void testGetSubjectAltName_OTHERNAME() {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
        final OtherName otherName = new OtherName();
        otherName.setValue("ROOT");
        subjectAltNameField.setValue(otherName);
        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        certificateUtil.getSubjectAltName(subjectAltName);

    }

    @Test
    public void testGetSubjectAltName_SubjectAltNameString() {

        final SubjectAltName subjectAltName = new SubjectAltName();

        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("ROOT");
        subjectAltNameField.setValue(subjectAltNameString);

        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        certificateUtil.getSubjectAltName(subjectAltName);

    }

}
