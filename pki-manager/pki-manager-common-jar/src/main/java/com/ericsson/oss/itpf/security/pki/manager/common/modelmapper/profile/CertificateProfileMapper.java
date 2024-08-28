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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import java.util.*;

import javax.enterprise.context.RequestScoped;
import javax.persistence.PersistenceException;
import javax.xml.datatype.*;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AbstractModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is used to map Certificate Profile from API Model to JPA Entity and JPA Entity to API Model. While mapping certificate profile from API Model to JPA Entity by using issuer name actual CA
 * Entity will be searched and retrieved from DB and mapped to JPA Entity and this is same in the case of algorithms too.
 *
 */
@RequestScoped
@ProfileQualifier(ProfileType.CERTIFICATE_PROFILE)
public class CertificateProfileMapper extends AbstractModelMapper {

    private final static String NAME_PATH = "certificateAuthorityData.name";

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
     *
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

        final Algorithm signatureAlgorithm = AlgorithmConfigurationModelMapper.fromAlgorithmData(certificateProfileData.getSignatureAlgorithm());
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
                certificateProfile.setIssuer(issuerToAPIFromModel(certificateProfileData.getIssuerData()));
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
            certificateProfile.setCertificateExtensions(JsonUtil.getObjectFromJson(CertificateExtensions.class, certificateProfileData.getCertificateExtensionsJSONData()));
        }

        certificateProfile.setProfileValidity(certificateProfileData.getProfileValidity());
        certificateProfile.setActive(certificateProfileData.isActive());
        certificateProfile.setSubjectCapabilities(JsonUtil.getObjectFromJson(Subject.class, certificateProfileData.getSubjectCapabilities()));

        logger.debug("Mapped CertificateProfile is {}", certificateProfile);
        return (T) certificateProfile;
    }

    /**
     * This method maps the API Model to its corresponding JPA Entity.
     *
     * @param profile
     *            Instance of {@link CertificateProfile}
     * @return Instance of {@link CertificateProfileData}
     * @throws ProfileServiceException
     *             Thrown when Invalid parameters are found in the profile data.
     *
     **/
    @Override
    public <T, E> E fromAPIToModel(final T profile) throws  ProfileServiceException {

        final CertificateProfile certificateProfile = (CertificateProfile) profile;
        logger.debug("Mapping CertificateProfile model to CertificateProfileData entity.", certificateProfile);

        final CertificateProfileData certificateProfileData = new CertificateProfileData();

        certificateProfileData.setId(certificateProfile.getId());
        certificateProfileData.setName(certificateProfile.getName());
        certificateProfileData.setVersion(certificateProfile.getVersion());
        certificateProfileData.setValidity(certificateProfile.getCertificateValidity().toString());
        certificateProfileData.setSubjectUniqueIdentifier(certificateProfile.isSubjectUniqueIdentifier());
        certificateProfileData.setIssuerUniqueIdentifier(certificateProfile.isIssuerUniqueIdentifier());
        certificateProfileData.setForCAEntity(certificateProfile.isForCAEntity());
        certificateProfileData.setActive(certificateProfile.isActive());
        certificateProfileData.setProfileValidity(certificateProfile.getProfileValidity());
        certificateProfileData.setSubjectCapabilities(JsonUtil.getJsonFromObject(certificateProfile.getSubjectCapabilities()));
        certificateProfileData.setModifiable(certificateProfile.isModifiable());

        if (certificateProfile.getSkewCertificateTime() != null) {
            certificateProfileData.setSkewCertificateTime(certificateProfile.getSkewCertificateTime().toString());
        }

        if (certificateProfile.getCertificateExtensions() != null) {
            final CertificateExtensions certificateExtensions = populateSubjectKeyIdentifierAlgorithm(certificateProfile.getCertificateExtensions());
            certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(certificateExtensions));
        }

        final AlgorithmData signatureAlgorithmData = populateSignatureAlgorithm(certificateProfile.getSignatureAlgorithm().getName());
        certificateProfileData.setSignatureAlgorithm(signatureAlgorithmData);

        final Set<AlgorithmData> algorithmDatas = new HashSet<AlgorithmData>();
        try{
            for (final Algorithm algorithm : certificateProfile.getKeyGenerationAlgorithms()) {
                algorithmDatas.add(populateKeyGenerationAlgorithm(algorithm.getName(), algorithm.getKeySize()));
            }

        } catch (final PKIConfigurationServiceException e) {
            logger.error("SQL Exception occurred while mapping Certificate API model to JPA model {}", e.getMessage());
            throw new ProfileServiceException("Occured in mapping Certificate  ", e);
        }
            certificateProfileData.setKeyGenerationAlgorithms(algorithmDatas);

        if (certificateProfile.getIssuer() != null) {
            final String issuername = certificateProfile.getIssuer().getCertificateAuthority().getName();
            final CAEntityData issuerData = populateCAEntityData(issuername);
            certificateProfileData.setIssuerData(issuerData);
        }

        logger.debug("Mapped CertificateProfileData is {}", certificateProfileData);

        return (E) certificateProfileData;
    }

    /**
     * @param certificateExtensions
     */
    private CertificateExtensions populateSubjectKeyIdentifierAlgorithm(final CertificateExtensions certificateExtensions) {
        if (certificateExtensions == null || ValidationUtils.isNullOrEmpty(certificateExtensions.getCertificateExtensions())) {
            return certificateExtensions;
        }

        for (final CertificateExtension certificateExtension : certificateExtensions.getCertificateExtensions()) {

            if (certificateExtension instanceof SubjectKeyIdentifier) {
                final Algorithm keyIdentifierAlgorithm = ((SubjectKeyIdentifier) certificateExtension).getKeyIdentifier().getAlgorithm();
                final AlgorithmData keyIdentifierAlgorithmData = populateKeyIdentifierAlgorithmData(keyIdentifierAlgorithm.getName());
                ((SubjectKeyIdentifier) certificateExtension).getKeyIdentifier().setAlgorithm(mapToAlgorithm(keyIdentifierAlgorithmData));
            }
        }

        return certificateExtensions;
    }

    /**
     * @param algorithmData
     * @return
     */
    private Algorithm mapToAlgorithm(final AlgorithmData algorithmData) {
        final Algorithm algorithm = new Algorithm();
        final List<AlgorithmCategory> categories = new ArrayList<AlgorithmCategory>();

        for (final Integer category : algorithmData.getCategories()) {
            categories.add(AlgorithmCategory.getCategory(category));
        }

        algorithm.setId(algorithmData.getId());
        algorithm.setKeySize(algorithmData.getKeySize());
        algorithm.setName(algorithmData.getName());
        algorithm.setCategories(categories);
        algorithm.setOid(algorithmData.getOid());
        algorithm.setSupported(algorithmData.isSupported());
        algorithm.setType(AlgorithmType.getType(algorithmData.getType()));

        return algorithm;
    }

    /**
     * @param issuer
     * @return
     */
    private CAEntityData populateCAEntityData(final String issuer) throws ProfileServiceException {
        CAEntityData cAEntityData = new CAEntityData();
        try {
            cAEntityData = persistenceManager.findEntityByName(CAEntityData.class, issuer, NAME_PATH);
        } catch (final PersistenceException e) {
            logger.error("SQL Exception occurred while retrieving CAs{} ", issuer, " in DB {}", e.getMessage());
            throw new ProfileServiceException("Occured in retrieving CAs", e);
        }
        return cAEntityData;
    }
}