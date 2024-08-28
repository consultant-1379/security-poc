/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509;

import java.io.FileNotFoundException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateRequestData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CSRExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc.CertificateBase;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class SubjectAltNameValidatorTest {

    @InjectMocks
    SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    CertificateExtensionUtils certificateExtensionUtils;

    @Mock
    CSRExtensionUtils csrExtensionUtils;

    @Mock
    Logger logger;

    CACertificateValidationInfo caCertificateValidationInfo = new CACertificateValidationInfo();
    CertificateBase certificateBase = new CertificateBase();
    String caName = "caName";
    X509Certificate x509Certificate = null;

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {

        caCertificateValidationInfo = setupData();

        SubjectAltName SAN = getSANFields("CN=testEntity");
        Mockito.when((SubjectAltName) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.SUBJECT_ALT_NAME)).thenReturn(SAN);
        subjectAltNameValidator.validate(caCertificateValidationInfo);
    }

    @Test(expected=MissingMandatoryFieldException.class)
    public void testMissingMandatoryFieldException() throws CertificateException, FileNotFoundException {
        caCertificateValidationInfo = setupData();

        SubjectAltName SAN = getSANFields("Test");
        Mockito.when((SubjectAltName) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.SUBJECT_ALT_NAME)).thenReturn(SAN);
        subjectAltNameValidator.validate(caCertificateValidationInfo);
    }

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testCertificateServiceException() throws CertificateException, FileNotFoundException {
        caCertificateValidationInfo = setupData();

        SubjectAltName SAN = getSANFields("Test");
        Mockito.when((SubjectAltName) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.SUBJECT_ALT_NAME)).thenThrow(CertificateServiceException.class);
        subjectAltNameValidator.validate(caCertificateValidationInfo);
    }
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testCertificateParseException() throws CertificateException, FileNotFoundException {
        caCertificateValidationInfo = setupData();

        SubjectAltName SAN = getSANFields("Test");
        Mockito.when((SubjectAltName) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.SUBJECT_ALT_NAME)).thenThrow(CertificateParsingException.class);
        subjectAltNameValidator.validate(caCertificateValidationInfo);
    }

    private CACertificateValidationInfo setupData() throws CertificateException, FileNotFoundException {

        x509Certificate = certificateBase.getX509Certificate("ExtRootCA.crt");

        caCertificateValidationInfo.setCertificate(x509Certificate);
        caCertificateValidationInfo.setCaName(caName);

        CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setCsr(x509Certificate.getEncoded());

        CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();
        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
        return caCertificateValidationInfo;
    }

    private SubjectAltName getSANFields(final String value) {
        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjAltNameField = new SubjectAltNameField();
        subjAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(value);
        subjAltNameField.setValue(subjectAltNameString);
        subjectAltNameFields.add(subjAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        return subjectAltName;
    }
}
