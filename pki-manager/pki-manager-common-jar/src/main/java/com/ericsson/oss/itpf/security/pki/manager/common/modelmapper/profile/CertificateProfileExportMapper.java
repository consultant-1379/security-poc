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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.*;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is used to map CertificateProfile from JPA Entity to API Model with only required fields used for Import profiles operation.
 *
 * @author xsusant
 */
public class CertificateProfileExportMapper extends CertificateProfileMapper {

    /**
     * This method maps the JPA Entity to its corresponding API Model.
     *
     * @param dataModel
     *            Instance of {@link CertificateProfileData}
     * @return Instance of {@link CertificateProfile}
     *
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid parameters are found in the profile data.
     */
    @Override
    public <T, E> T toAPIFromModel(final E profileData) throws CANotFoundException, InvalidProfileAttributeException {

        final CertificateProfileData certificateProfileData = (CertificateProfileData) profileData;
        logger.debug("Mapping CertificateProfileData entity to CertificateProfile model.", certificateProfileData);

        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(certificateProfileData.getId());
        certificateProfile.setName(certificateProfileData.getName());
        certificateProfile.setVersion(certificateProfileData.getVersion());
        certificateProfile.setForCAEntity(certificateProfileData.isForCAEntity());
        certificateProfile.setModifiable(certificateProfileData.isModifiable());

        final List<AlgorithmData> keyGenerationAlgorithmDataList = new ArrayList<AlgorithmData>(certificateProfileData.getKeyGenerationAlgorithms());
        final List<Algorithm> keyGenerationAlgorithmList = AlgorithmConfigurationModelMapper.fromAlgorithmData(keyGenerationAlgorithmDataList);
        certificateProfile.setKeyGenerationAlgorithms(keyGenerationAlgorithmList);
        final Algorithm signatureAlgorithm = AlgorithmConfigurationModelMapper
                .fromAlgorithmDataForImport(certificateProfileData.getSignatureAlgorithm());
        certificateProfile.setSignatureAlgorithm(signatureAlgorithm);

        if (certificateProfileData.getValidity() != null) {
            DatatypeFactory d = null;
            try {
                d = DatatypeFactory.newInstance();
            } catch (final DatatypeConfigurationException datatypeConfigurationException) {
                logger.error("SQL Exception occurred while validating Certificate Profile. {}", datatypeConfigurationException.getMessage());
                throw new InvalidProfileAttributeException(ProfileServiceErrorCodes.OCCURED_IN_VALIDATING, datatypeConfigurationException);
            }
            final Duration validity = d.newDuration(certificateProfileData.getValidity());
            certificateProfile.setCertificateValidity(validity);
        }

        try {
            if (certificateProfileData.getIssuerData() != null) {
                final CAEntity caEntity = getCAEntity(certificateProfileData.getIssuerData());
                certificateProfile.setIssuer(caEntity);
            }
        } catch (final EntityNotFoundException ex) {
            throw new CANotFoundException(ProfileServiceErrorCodes.GIVEN_ISSUER + ProfileServiceErrorCodes.NOT_FOUND, ex);
        }

        certificateProfile.setIssuerUniqueIdentifier(certificateProfileData.isIssuerUniqueIdentifier());
        certificateProfile.setSubjectUniqueIdentifier(certificateProfileData.isSubjectUniqueIdentifier());

        if (certificateProfileData.getSkewCertificateTime() != null) {
            DatatypeFactory d = null;
            try {
                d = DatatypeFactory.newInstance();
            } catch (final DatatypeConfigurationException datatypeConfigurationException) {
                logger.error("SQL Exception occurred while validating Certificate Profile. {}", datatypeConfigurationException.getMessage());
                throw new InvalidProfileAttributeException(ProfileServiceErrorCodes.OCCURED_IN_VALIDATING, datatypeConfigurationException);
            }
            final Duration skewTime = d.newDuration(certificateProfileData.getSkewCertificateTime());
            certificateProfile.setSkewCertificateTime(skewTime);
        }

        if (certificateProfileData.getCertificateExtensionsJSONData() != null) {
            certificateProfile.setCertificateExtensions(
                    JsonUtil.getObjectFromJson(CertificateExtensions.class, certificateProfileData.getCertificateExtensionsJSONData()));
        }

        certificateProfile.setProfileValidity(certificateProfileData.getProfileValidity());
        certificateProfile.setSubjectCapabilities(JsonUtil.getObjectFromJson(Subject.class, certificateProfileData.getSubjectCapabilities()));

        logger.debug("Mapped CertificateProfile is {}", certificateProfile);
        return (T) certificateProfile;
    }

    private CAEntity getCAEntity(final CAEntityData caEntityData) {
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());

        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);
        return caEntity;
    }
}
