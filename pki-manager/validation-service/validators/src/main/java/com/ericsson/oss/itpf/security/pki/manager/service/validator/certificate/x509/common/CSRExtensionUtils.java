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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common;

import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateRequestUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;

/**
 * This is a utility class to fetch Extensions from CSR.
 * 
 * @author tcsramc
 *
 */
public class CSRExtensionUtils {
    @Inject
    Logger logger;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    /**
     * This method is used to fetch extension value from the CSR.
     * 
     * @param caName
     *            based on which CSR will be fetched.
     * @param aSN1ObjectIdentifier
     *            attributeID( ASN1ObjectIdentifier object) for which extension has to be fetched.
     * @return extension value in byte array
     * @throws CertificateServiceException
     *             is thrown if any error occured while fetching CSR from the database.
     * @throws MissingMandatoryFieldException
     *             is thrown if particular extension is not present in the CSR.
     */
    public byte[] getCSRAttributeExtensionValue(final String caName, final ASN1ObjectIdentifier aSN1ObjectIdentifier) throws CertificateServiceException, MissingMandatoryFieldException {

        final CertificateGenerationInfoData certificateGenerationInfoData = caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName);
        final byte[] certificateRequest = certificateGenerationInfoData.getCertificateRequestData().getCsr();
        final byte[] csrAuthorityInfoAccessExtensionValue = CertificateRequestUtility.getAttributeExtensionValue(certificateRequest, aSN1ObjectIdentifier);

        return csrAuthorityInfoAccessExtensionValue;
    }

    /**
     * This method is used to get Certificate Extension from the CSR based on given caName and CertificateExtensionType.
     * 
     * @param caName
     *            based on which CSR has to be fetched.
     * @param certExtensionTypeToVerify
     *            Extension Object which has to be fetched from CSR
     * @return certificateExtension Object
     * @throws CertificateServiceException
     *             is thrown if any error occured while fetching CSR from the database.
     */
    public CertificateExtension getCSRExtension(final String caName, final CertificateExtensionType certExtensionTypeToVerify) throws CertificateServiceException {
        CertificateExtension certExtension = null;
        final CertificateGenerationInfoData certificateGenerationInfoData = caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName);
        final CertificateExtensions certificateExtensionsJson = JsonUtil.getObjectFromJson(CertificateExtensions.class, certificateGenerationInfoData.getCertificateExtensionsJSONData());
        final List<CertificateExtension> certificateExtensions = certificateExtensionsJson.getCertificateExtensions();

        for (final CertificateExtension certifiateExtension : certificateExtensions) {
            if (certifiateExtension != null) {
                final CertificateExtensionType certificateExtensionType = CertificateExtensionType.getCertificateExtensionType(certifiateExtension.getClass().getSimpleName());
                if (certificateExtensionType.equals(certExtensionTypeToVerify)) {
                    certExtension = certifiateExtension;
                    break;
                }
            }
        }
        return certExtension;
    }
}
