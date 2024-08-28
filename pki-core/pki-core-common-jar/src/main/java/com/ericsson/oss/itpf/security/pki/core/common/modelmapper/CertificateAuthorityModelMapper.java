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

import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

public class CertificateAuthorityModelMapper {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CRLInfoMapper crlInfoMapper;

    @Inject
    CRLGenerationInfoMapper cRLGenerationInfoMapper;

    @Inject
    CertificateModelMapper certificateModelMapper;

    private static final String NAME_PATH = "name";

    /**
     * Converting {@link CertificateAuthority} API model to {@link CertificateAuthorityData} entity.
     * 
     * @param certificateAuthority
     *            object that to be converted to JPA entity.
     * @param operationType
     * @return converted {@link CertificateAuthorityData} entity.
     * @throws CoreEntityServiceException
     *             thrown for any entity related database errors in PKI Core.
     */
    public CertificateAuthorityData fromAPIModel(final CertificateAuthority certificateAuthority, final OperationType operationType) throws CoreEntityServiceException {

        logger.debug("Mapping CertificateAuthority domain model {} to CertificateAuthority entity.", certificateAuthority);

        CertificateAuthorityData certificateAuthorityData = null;
        CertificateAuthorityData issuerData = null;

        try {
            if (operationType.equals(OperationType.UPDATE)) {
                certificateAuthorityData = persistenceManager.findEntity(CertificateAuthorityData.class, certificateAuthority.getId());
            }

            if (certificateAuthorityData == null) {
                certificateAuthorityData = new CertificateAuthorityData();
            }
            certificateAuthorityData.setId((int) certificateAuthority.getId());
            certificateAuthorityData.setName(certificateAuthority.getName());
            certificateAuthorityData.setRootCA(certificateAuthority.isRootCA());
            certificateAuthorityData.setStatus(certificateAuthority.getStatus());
            if (certificateAuthority.getSubject() != null) {
                certificateAuthorityData.setSubjectDN(certificateAuthority.getSubject().toASN1String());
            }
            if (certificateAuthority.getSubjectAltName() != null) {
                certificateAuthorityData.setSubjectAltName(JsonUtil.getJsonFromObject(certificateAuthority.getSubjectAltName()));
            }

            if (certificateAuthority.getIssuer() != null && certificateAuthority.getIssuer().getName() != null) {
                issuerData = persistenceManager.findEntityByName(CertificateAuthorityData.class, certificateAuthority.getIssuer().getName(), NAME_PATH);
            }
        } catch (final PersistenceException e) {
            logger.error("Exception occurred while retrieving entity: {}", e.getMessage());
            throw new CoreEntityServiceException("Exception occurred while retrieving entity", e);
        }

        certificateAuthorityData.setIssuerCA(issuerData);

        if (ValidationUtils.isNullOrEmpty(certificateAuthorityData.getCrlGenerationInfo()) && !ValidationUtils.isNullOrEmpty(certificateAuthority.getCrlGenerationInfo())) {
            certificateAuthorityData.setCrlGenerationInfo(cRLGenerationInfoMapper.fromAPIModel(certificateAuthority.getCrlGenerationInfo()));
        }

        certificateAuthorityData.setPublishToCDPS(certificateAuthority.isPublishToCDPS());
        logger.debug("Mapped CertificateAuthorityData entity is {}", certificateAuthorityData);
        return certificateAuthorityData;
    }

    /**
     * Maps the CertificateAuthority JPA model to its corresponding API model
     * 
     * @param certificateAuthorityData
     *            CertificateAuthorityData Object which should be converted to API model CertificateAuthority
     * @return Returns the API model of the given JPA model
     * @throws CRLServiceException
     *             Thrown, if any database failures occurs in case of CRL operations.
     * @throws InvalidCertificateException
     *             thrown when Invalid certificate is found for entity.
     * @throws InvalidCRLGenerationInfoException
     *             in case of mapping the CRLGenerationInfo from JPA to model is failed
     */
    public CertificateAuthority toAPIModel(final CertificateAuthorityData certificateAuthorityData) throws CRLServiceException, InvalidCertificateException, InvalidCRLGenerationInfoException {

        logger.debug("Mapping CertificateAuthorityData entity {} to CertificateAuthority domain model.", certificateAuthorityData.getId());

        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        try {
            certificateAuthority.setId(certificateAuthorityData.getId());
            certificateAuthority.setName(certificateAuthorityData.getName());
            if (certificateAuthorityData.getSubjectDN() != null && !certificateAuthorityData.getSubjectDN().isEmpty()) {
                final Subject subject = new Subject();
                certificateAuthority.setSubject(subject.fromASN1String(certificateAuthorityData.getSubjectDN()));
            }
            if (certificateAuthorityData.getSubjectAltName() != null && !certificateAuthorityData.getSubjectAltName().isEmpty()) {
                certificateAuthority.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, certificateAuthorityData.getSubjectAltName()));
            }
            certificateAuthority.setRootCA(certificateAuthorityData.isRootCA());
            certificateAuthority.setStatus(certificateAuthorityData.getStatus());

            if (!certificateAuthorityData.isRootCA() && certificateAuthorityData.getIssuerCA() != null) {
                certificateAuthority.setIssuer(toAPIModel(certificateAuthorityData.getIssuerCA()));
            }
            certificateAuthority.setPublishToCDPS(certificateAuthorityData.isPublishToCDPS());

            setCertificates(certificateAuthorityData, certificateAuthority);

            setCrlInfo(certificateAuthorityData, certificateAuthority);

            if (certificateAuthorityData.getCrlGenerationInfo() != null && !certificateAuthorityData.getCrlGenerationInfo().isEmpty()) {
                certificateAuthority.setCrlGenerationInfo(cRLGenerationInfoMapper.toAPIModel(certificateAuthorityData.getCrlGenerationInfo()));
            }

            logger.debug("Mapped CertificateAuthority domain model is {}", certificateAuthority);

        } catch (final CertificateException e) {
            logger.error("Invalid encoding of certificate: {}", e.getMessage());
            throw new InvalidCertificateException(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, e);
        }
        return certificateAuthority;
    }

    /**
     * @param certificateAuthorityData
     * @param certificateAuthority
     */
    private void setCrlInfo(final CertificateAuthorityData certificateAuthorityData, final CertificateAuthority certificateAuthority) throws CRLServiceException, InvalidCertificateException {
        final List<CRLInfo> crlList = new ArrayList<>();
        final Set<CRLInfoData> crlInfo = certificateAuthorityData.getCrlInfoDatas();
        if (crlInfo != null) {

            for (CRLInfoData crlData : crlInfo) {
                crlList.add(crlInfoMapper.toAPIFromModel(crlData));
            }
        }

        certificateAuthority.setCrlInfo(crlList);
    }

    /**
     * @param certificateAuthorityData
     * @param certificateAuthority
     * @throws CertificateException
     */
    private void setCertificates(final CertificateAuthorityData certificateAuthorityData, final CertificateAuthority certificateAuthority) throws CertificateException {
        final Set<CertificateData> certificates = certificateAuthorityData.getCertificateDatas();
        final List<Certificate> inactiveCertificates = new ArrayList<>();
        if (certificates != null) {
            final Iterator<CertificateData> it = certificates.iterator();
            while (it.hasNext()) {
                final CertificateData certificateData = it.next();
                if (certificateData.getStatus() == CertificateStatus.ACTIVE) {
                    certificateAuthority.setActiveCertificate(certificateModelMapper.mapToCertificate(certificateData));
                } else {
                    inactiveCertificates.add(certificateModelMapper.mapToCertificate(certificateData));
                }
            }
            certificateAuthority.setInActiveCertificates(inactiveCertificates);
        }
    }
}
