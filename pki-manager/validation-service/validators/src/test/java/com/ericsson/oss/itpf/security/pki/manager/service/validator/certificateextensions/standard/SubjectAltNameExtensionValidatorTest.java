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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.standard;

import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
//import com.ericsson.oss.itpf.security.pki.manager.common.persistence.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SubjectAltNameExtensionValidatorTest {

    @Mock
    private Logger logger;

    @InjectMocks
    private SubjectAltNameExtensionValidator subjectAltNameExtensionValidator;

    private SubjectAltName subjectAltName;

    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        for (final CertificateExtension certificateExtension : certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions()
                .getCertificateExtensions()) {
            if (certificateExtension != null) {
                if (certificateExtension.getClass().getSimpleName().equals(CertificateExtensionType.SUBJECT_ALT_NAME.getName())) {
                    subjectAltName = (SubjectAltName) certificateExtension;
                }
            }
        }
    }

    @Test
    public void testValidate() {
        subjectAltNameExtensionValidator.validate(subjectAltName, true, "TestIssuer");
        verify(logger).debug("Validating SubjectAltName in CertificateProfile{}", subjectAltName);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateSubjectAltNameWithNull() {
        subjectAltName.setSubjectAltNameFields(null);
        subjectAltNameExtensionValidator.validate(subjectAltName, true, "TestIssuer");
    }

    @Test
    public void testValidateSubjectNull() {
        subjectAltName = null;
        subjectAltNameExtensionValidator.validate(subjectAltName, true, "TestIssuer");
        verify(logger).debug("Validating SubjectAltName in CertificateProfile{}", subjectAltName);

    }

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateSubjectAltNameFiledsTypeNull() {
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjAltNameField = new SubjectAltNameField();
        subjAltNameField.setType(null);
        subjectAltNameFields.add(subjAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        subjectAltNameExtensionValidator.validate(subjectAltName, true, "TestIssuer");
    }

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateSubjectAltNameFiledsValueNull() {
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjAltNameField = new SubjectAltNameField();
        subjAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("Test");
        subjAltNameField.setValue(subjectAltNameString);
        subjectAltNameFields.add(subjAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        subjectAltNameExtensionValidator.validate(subjectAltName, true, "TestIssuer");
    }
}
