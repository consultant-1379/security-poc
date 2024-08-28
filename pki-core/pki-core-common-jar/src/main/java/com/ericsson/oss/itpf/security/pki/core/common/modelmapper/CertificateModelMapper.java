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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

/**
 * Class to perform mapping between Object model and JPA model
 * 
 */
public class CertificateModelMapper {

    @Inject
    DateUtil dateUtil;

    @Inject
    CertificateGenerationInfoParser certificateGenerationInfoParser;

    @Inject
    Logger logger;

    @Inject
    CertificatePersistenceHelper persistenceHelper;

    /**
     * Maps {@link CertificateGenerationInfo} model to {@link CertificateGenerationInfoData} JPA entity.
     * 
     * @param certGenerationInfo
     *            {@link CertificateGenerationInfo} model to be mapped.
     * @param certificationRequest
     * @param certificateAuthorityData
     *            {@link CertificateAuthorityData} that to be mapped for {@link CertificateGenerationInfoData}
     * @param entityData
     *            {@link EntityInfoData} that to be mapped for {@link CertificateGenerationInfoData}
     * @return {@link CertificateGenerationInfoData} that is mapped from {@link CertificateGenerationInfo}
     * @throws CoreEntityNotFoundException
     *             thrown when given Entity doesn't exists.
     * @throws CoreEntityServiceException
     *             thrown for any entity related database errors in PKI Core.
     */

    public CertificateGenerationInfoData mapToCertificateGenerationInfoData(final CertificateGenerationInfo certGenerationInfo, final byte[] certificationRequest,
            final CertificateAuthorityData certificateAuthorityData, final EntityInfoData entityData) throws CoreEntityNotFoundException, CoreEntityServiceException {

        final CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();
        certificateGenerationInfoData.setId(certGenerationInfo.getId());
        certificateGenerationInfoData.setValidity(certGenerationInfo.getValidity().toString());
        if (certGenerationInfo.getSkewCertificateTime() != null) {
            certificateGenerationInfoData.setSkewCertificateTime(certGenerationInfo.getSkewCertificateTime().toString());
        }
        certificateGenerationInfoData.setCertificateVersion(certGenerationInfo.getVersion());
        certificateGenerationInfoData.setSubjectUniqueIdentifier(certGenerationInfo.isSubjectUniqueIdentifier());
        certificateGenerationInfoData.setSubjectUniqueIdentifierValue(certGenerationInfo.getSubjectUniqueIdentifierValue());
        certificateGenerationInfoData.setIssuerUniqueIdentifier(certGenerationInfo.isIssuerUniqueIdentifier());
        certificateGenerationInfoData.setRequestType(certGenerationInfo.getRequestType());

        certificateGenerationInfoData.setKeyGenerationAlgorithmData(persistenceHelper.getAlgorithmData(certGenerationInfo.getKeyGenerationAlgorithm()));
        certificateGenerationInfoData.setSignatureAlgorithmData(persistenceHelper.getAlgorithmData(certGenerationInfo.getSignatureAlgorithm()));
        certificateGenerationInfoData.setIssuerSignatureAlgorithmData(persistenceHelper.getAlgorithmData(certGenerationInfo.getIssuerSignatureAlgorithm()));

        if (certGenerationInfo.getCAEntityInfo() != null) {
            certificateGenerationInfoData.setcAEntityInfo(certificateAuthorityData);
            if (certGenerationInfo.getCAEntityInfo().isRootCA()) {
                certificateGenerationInfoData.setIssuerCA(certificateAuthorityData);
            } else {
                certificateGenerationInfoData.setIssuerCA(persistenceHelper.getCA(certGenerationInfo.getIssuerCA().getName()));
            }
        } else {
            certificateGenerationInfoData.setEntityInfo(entityData);
            certificateGenerationInfoData.setIssuerCA(persistenceHelper.getCA(certGenerationInfo.getIssuerCA().getName()));
        }

        final CertificateRequestData certificateRequestData = new CertificateRequestData();

        certificateRequestData.setCsr(certificationRequest);
        certificateRequestData.setStatus(CertificateRequestStatus.NEW.getId());
        certificateGenerationInfoData.setForExternalCA(certGenerationInfo.isForExternalCA());

        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
        certificateGenerationInfoData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(certGenerationInfo.getCertificateExtensions(), false));

        return certificateGenerationInfoData;
    }

    /**
     * Maps {@link CertificateAuthorityData} JPA entity to {@link CertificateAuthority} object model.
     * 
     * @param certificateAuthorityData
     *            {@link CertificateAuthorityData} object .
     * @return CertificateAuthority object.
     */
    private CertificateAuthority mapToCertificateAuthority(final CertificateAuthorityData certificateAuthorityData) {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(certificateAuthority.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());
        return certificateAuthority;
    }

    /**
     * Maps {@link Certificate} model from {@link CertificateData}.
     * 
     * @param certificateData
     *            {@link CertificateData} object to prepare certificate model.
     * @return Certificate model from certificate generation info.
     * @throws CertificateException
     */

    public Certificate mapToCertificate(final CertificateData certificateData) throws CertificateException {
        logger.debug("Mapping Certificate having Subject DN: {} to the Certificate authority", certificateData.getSubjectDN());
        final Certificate certificateModel = new Certificate();
        certificateModel.setId(certificateData.getId());
        certificateModel.setNotBefore(certificateData.getNotBefore());
        certificateModel.setNotAfter(certificateData.getNotAfter());
        certificateModel.setIssuedTime(certificateData.getIssuedTime());
        certificateModel.setSerialNumber(certificateData.getSerialNumber());
        certificateModel.setStatus(certificateData.getStatus());
        certificateModel.setRevokedTime(certificateData.getRevokedTime());
        certificateModel.setSubject(new Subject().fromASN1String(certificateData.getSubjectDN()));
        if (certificateData.getSubjectAltName() != null && !certificateData.getSubjectAltName().isEmpty()) {
            certificateModel.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, certificateData.getSubjectAltName()));
        }
        if (certificateData.getIssuerCA() != null) {
            final CertificateAuthority certificateAuthority = mapToCertificateAuthority(certificateData.getIssuerCA());
            certificateModel.setIssuer(certificateAuthority);
        }
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        final InputStream in = new ByteArrayInputStream(certificateData.getCertificate());
        final X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
        certificateModel.setX509Certificate(cert);
        return certificateModel;
    }

    /**
     * Maps the {@link KeyPair} to {@link KeyIdentifierData} JPA.
     * 
     * @param keyIdentifier
     *            keyIdentifier
     * @param keyPairStatus
     *            Status of the keys whether active or not.
     * @return Mapped JPA {@link KeyIdentifierData}
     */
    public KeyIdentifierData mapToKeyData(final KeyIdentifier keyIdentifier, final KeyPairStatus keyPairStatus) {

        final KeyIdentifierData keyData = new KeyIdentifierData();
        keyData.setKeyIdentifier(keyIdentifier.getId());
        keyData.setStatus(keyPairStatus);

        return keyData;
    }
}
