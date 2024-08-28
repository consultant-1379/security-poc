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

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidExtendedKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateRequestData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CSRExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc.CertificateBase;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class ExtendedKeyUsageValidatorTest {

    @InjectMocks
    ExtendedKeyUsageValidator extendedKeyUsageValidator;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    CertificateExtensionUtils certificateExtensionUtils;

    @Mock
    CSRExtensionUtils csrExtensionUtils;

    @Mock
    ExtendedKeyUsage keyUsage;

    @Mock
    Logger logger;

    CACertificateValidationInfo caCertificateValidationInfo = new CACertificateValidationInfo();
    CertificateBase certificateBase = new CertificateBase();
    String caName = "caName";
    X509Certificate x509Certificate = null;

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidate() throws CertificateException, IOException {

        caCertificateValidationInfo = setupData();
        List<String> extKeyIds = caCertificateValidationInfo.getCertificate().getExtendedKeyUsage();

        Mockito.when((ExtendedKeyUsage) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.EXTENDED_KEY_USAGE)).thenReturn(keyUsage);
        byte[] extensionValue = x509Certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        final org.bouncycastle.asn1.x509.KeyPurposeId[] keyPurposeIDs = getKeyPurposeID(extensionValue, caName);
        Mockito.when(certificateExtensionUtils.getKeyPurposeID(extensionValue)).thenReturn(keyPurposeIDs);

        extendedKeyUsageValidator.validate(caCertificateValidationInfo);
        Mockito.verify(logger).error(ErrorMessages.EXTENDED_KEY_USAGE_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_EXTENDED_KEY_USAGE);
    }

    private CACertificateValidationInfo setupData() throws CertificateException, FileNotFoundException {

        x509Certificate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        caCertificateValidationInfo.setCertificate(x509Certificate);
        caCertificateValidationInfo.setCaName(caName);

        CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setCsr(x509Certificate.getEncoded());

        CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();
        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
        return caCertificateValidationInfo;
    }

    public KeyPurposeId[] getKeyPurposeID(final byte[] extensionValue, final String caName) throws InvalidExtendedKeyUsageExtension {
        final KeyPurposeId[] keyPurposeIDs;
        try {
            ASN1InputStream localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(extensionValue));

            localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString) localASN1InputStream.readObject()).getOctets()));

            final org.bouncycastle.asn1.x509.ExtendedKeyUsage localExtendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(localASN1InputStream.readObject());

            keyPurposeIDs = localExtendedKeyUsage.getUsages();
        } catch (IOException iOException) {
            logger.error(ErrorMessages.IO_EXCEPTION, "for CA {} ", caName, iOException.getMessage());
            throw new InvalidExtendedKeyUsageExtension(ErrorMessages.IO_EXCEPTION, iOException);
        }
        return keyPurposeIDs;
    }

}
