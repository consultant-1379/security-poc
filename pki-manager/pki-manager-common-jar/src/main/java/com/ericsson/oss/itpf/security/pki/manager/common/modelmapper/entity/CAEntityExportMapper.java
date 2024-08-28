/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Set;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is used to map CAEntity from JPA Entity to API Model with only required fields used for Import entities operation.
 *
 * @author xsusant
 */
public class CAEntityExportMapper extends CAEntityMapper {

    

    /**
     * Maps the CA Entity JPA model to its corresponding API model
     *
     * @param entityData
     *            CAEntityData Object which should be converted to API model CAEntity
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws CAEntityNotInternalException
     *             Thrown when given CA Entity exists but it's an external CA.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping CA Entity
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T, E> T toAPIFromModel(final E entityData) throws CAEntityNotInternalException, InvalidEntityAttributeException {

        final CAEntityData caEntityData = (CAEntityData) entityData;

        logger.debug("Mapping CAEntityData entity {} to CAEntity domain model.", caEntityData.getId());
        final CertificateAuthority certificateAuthority = getCertificateAuthority(caEntityData);

        if (caEntityData.isExternalCA()) {
            throw new CAEntityNotInternalException(ProfileServiceErrorCodes.CA_ENTITY_IS_EXTERNAL);
        }
        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);

        if (caEntityData.getKeyGenerationAlgorithm() != null) {
            caEntity.setKeyGenerationAlgorithm(
                    AlgorithmConfigurationModelMapper.fromAlgorithmDataForImport(caEntityData.getKeyGenerationAlgorithm()));
        }

        final EntityProfileData entityProfileData = caEntityData.getEntityProfileData();
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setActive(entityProfileData.isActive());
        entityProfile.setModifiable(entityProfileData.isModifiable());
        entityProfile.setName(entityProfileData.getName());
        entityProfile.setId(entityProfileData.getId());
        caEntity.setEntityProfile(entityProfile);

        caEntity.setPublishCertificatetoTDPS(caEntityData.isPublishCertificatetoTDPS());

        final Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet = caEntityData
                .getCertificateExpiryNotificationDetailsData();
        if (!ValidationUtils.isNullOrEmpty(certExpiryNotificationDetailsDataSet)) {
            caEntity.setCertificateExpiryNotificationDetails(
                    certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet));
        }
        logger.debug("Mapped CAEntity domain model is {}", caEntity);

        return (T) caEntity;
    }

    private CertificateAuthority getCertificateAuthority(final CAEntityData caEntityData) throws InvalidEntityAttributeException {
        if (caEntityData == null) {
            return null;
        }

        final CertificateAuthority certificateAuthority = toCertAuthAPIModel(caEntityData);
        final CAEntityData issuerData = caEntityData.getCertificateAuthorityData().getIssuer();
        if (issuerData != null) {
            certificateAuthority.setIssuer(toCertAuthAPIModel(issuerData));
        }

        return certificateAuthority;
    }

    private CertificateAuthority toCertAuthAPIModel(final CAEntityData caEntityData) {
        if (caEntityData == null) {
            return null;
        }

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());
        certificateAuthority.setSubject(toSubject(certificateAuthorityData.getSubjectDN()));
        certificateAuthority.setSubjectAltName(toSubjectAltName(certificateAuthorityData.getSubjectAltName()));
        certificateAuthority.setRootCA(certificateAuthorityData.isRootCA());
        certificateAuthority.setStatus(CAStatus.getStatus(certificateAuthorityData.getStatus()));
        certificateAuthority.setPublishToCDPS(certificateAuthorityData.isPublishToCDPS());
        certificateAuthority.setIssuerExternalCA(certificateAuthorityData.isIssuerExternalCA());
        try {
            certificateAuthority
                    .setCrlGenerationInfo(cRLGenerationInfoMapper.toAPIFromModelForImport(certificateAuthorityData.getCrlGenerationInfo()));
        } catch (InvalidCRLGenerationInfoException | CertificateException | IOException e) {
            logger.error(ErrorMessages.INVALID_CRL_GENERATION_INFO_FOR_CA + certificateAuthorityData.getName());
            logger.debug(ErrorMessages.INVALID_CRL_GENERATION_INFO_FOR_CA + certificateAuthorityData.getName(), e);
        }

        return certificateAuthority;
    }

}
