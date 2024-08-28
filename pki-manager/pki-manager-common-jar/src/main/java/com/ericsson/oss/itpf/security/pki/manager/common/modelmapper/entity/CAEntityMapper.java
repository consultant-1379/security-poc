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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.*;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.*;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.EntityProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RequestScoped
@EntityQualifier(EntityType.CA_ENTITY)
public class CAEntityMapper extends AbstractModelMapper {

    @Inject
    @ProfileQualifier(ProfileType.ENTITY_PROFILE)
    EntityProfileMapper entityProfileMapper;

    @Inject
    CRLInfoMapper crlMapper;


    @Inject
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

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
        final CertificateAuthority certificateAuthority = toCertAuthAPIModel(caEntityData, true);

        if (caEntityData.isExternalCA()) {
            throw new CAEntityNotInternalException(ProfileServiceErrorCodes.CA_ENTITY_IS_EXTERNAL);
        }
        final CAEntity caEntity = new CAEntity();

        caEntity.setCertificateAuthority(certificateAuthority);

        if (caEntityData.getKeyGenerationAlgorithm() != null) {
            caEntity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(caEntityData.getKeyGenerationAlgorithm()));
        }

        caEntity.setEntityProfile((EntityProfile) entityProfileMapper.toAPIFromModel(caEntityData.getEntityProfileData()));
        caEntity.setPublishCertificatetoTDPS(caEntityData.isPublishCertificatetoTDPS());
        final Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet = caEntityData.getCertificateExpiryNotificationDetailsData();
        if (!ValidationUtils.isNullOrEmpty(certExpiryNotificationDetailsDataSet)) {
            caEntity.setCertificateExpiryNotificationDetails(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet));
        }
        logger.debug("Mapped CAEntity domain model is {}", caEntity);

        return (T) caEntity;
    }

    @SuppressWarnings("unchecked")
    public <T, E> T toAPIFromModelForCAName(final E entityData) {

        final CAEntityData caEntityData = (CAEntityData) entityData;
         CertificateAuthority certificateAuthority = null;
         final CAEntity caEntity = new CAEntity();

        if (caEntityData != null) {
            logger.debug("Mapping CAEntityData entity {} to CAEntity domain model.", caEntityData.getId());
             if (caEntityData.isExternalCA()) {
                 throw new CAEntityNotInternalException(ProfileServiceErrorCodes.CA_ENTITY_IS_EXTERNAL);
             }
        certificateAuthority = new CertificateAuthority();
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();
        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());

        if (caEntityData.getKeyGenerationAlgorithm() != null) {
            caEntity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(caEntityData.getKeyGenerationAlgorithm()));
        }

        caEntity.setCertificateAuthority(certificateAuthority);
        }

        return (T) caEntity;
    }

    /**
     * Maps the CA Entity JPA model to its corresponding API model model with embeddedObjectsRequired
     *
     * @param entityData
     *            CAEntityData Object which should be converted to API model CAEntity
     *
     * @param embeddedObjectsRequired
     *            Attribute to define if embedded objects are required or not
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws CAEntityNotInternalException
     *             Thrown when given CA Entity exists but it's an external CA.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping CA Entity
     */
    public <T, E> T toAPIFromModel(final E entityData, final boolean embeddedObjectsRequired)
            throws CAEntityNotInternalException, InvalidEntityAttributeException {

        final CAEntityData caEntityData = (CAEntityData) entityData;

        logger.debug("Mapping CAEntityData entity {} to CAEntity domain model with embeddedObjectsRequired {}", caEntityData.getId(),
                embeddedObjectsRequired);
        final CertificateAuthority certificateAuthority = toCertAuthAPIModel(caEntityData, embeddedObjectsRequired);
        if (caEntityData.isExternalCA()) {
            throw new CAEntityNotInternalException(ProfileServiceErrorCodes.CA_ENTITY_IS_EXTERNAL);
        }
        final CAEntity caEntity = new CAEntity();

        caEntity.setCertificateAuthority(certificateAuthority);
        caEntity.setPublishCertificatetoTDPS(caEntityData.isPublishCertificatetoTDPS());

        if (embeddedObjectsRequired) {

            if (caEntityData.getKeyGenerationAlgorithm() != null) {
                caEntity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(caEntityData.getKeyGenerationAlgorithm()));
            }

            caEntity.setEntityProfile((EntityProfile) entityProfileMapper.toAPIFromModel(caEntityData.getEntityProfileData()));

            final Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet = caEntityData.getCertificateExpiryNotificationDetailsData();
            if (!ValidationUtils.isNullOrEmpty(certExpiryNotificationDetailsDataSet)) {
                caEntity.setCertificateExpiryNotificationDetails(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet));
            }
        }
        logger.debug("Mapped CAEntity domain model for caEntity {}", caEntity.getCertificateAuthority().getName());

        return (T) caEntity;
    }

    /**
     * Maps the CA Entity API model to its corresponding JPA model
     *
     * @param entityData
     *            CAEntity Object which should be converted to JPA model CAEntityData
     *
     * @return Returns the JPA model of the given API model
     *
     * @throws EntityServiceException
     *             thrown when any internal Database errors occur.
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T, E> E fromAPIToModel(final T APIModel) throws EntityServiceException {
        final CAEntityData caEntityData = new CAEntityData();
        final CAEntity caEntity = (CAEntity) APIModel;
        logger.debug("Mapping CAEntity domain model {} to CAEntityData entity.", caEntity);

        final CertificateAuthority certificateAuthority = caEntity.getCertificateAuthority();

        caEntityData.setId(certificateAuthority.getId());
        caEntityData.setPublishCertificatetoTDPS(caEntity.isPublishCertificatetoTDPS());
        try {
            final EntityProfileData entityProfileData = populateEntityProfileData(caEntity.getEntityProfile().getName());
            caEntityData.setEntityProfileData(entityProfileData);
            if (caEntity.getKeyGenerationAlgorithm() != null) {
                caEntityData.setKeyGenerationAlgorithm(populateKeyGenerationAlgorithm(caEntity.getKeyGenerationAlgorithm().getName(), caEntity.getKeyGenerationAlgorithm().getKeySize()));
            }
            final CertificateAuthorityData certificateAuthorityData = fromAPIToModelCertAuth(certificateAuthority);

            certificateAuthorityData.setIssuer(entityProfileData.getCertificateProfileData().getIssuerData());
            certificateAuthorityData.setRootCA(isRootCA(entityProfileData));

            caEntityData.setCertificateAuthorityData(certificateAuthorityData);
            caEntityData.setExternalCA(false);
        } catch (final CRLServiceException | PKIConfigurationServiceException | ProfileServiceException e) {
            logger.error("SQL Exception occurred while mapping CA Entity API model to JPA model {}", e.getMessage());
            throw new EntityServiceException("Occured in mapping CA Entity ", e);
        }
        final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = caEntity.getCertificateExpiryNotificationDetails();
        if (!ValidationUtils.isNullOrEmpty(certificateExpiryNotificationDetails)) {
            caEntityData.setCertificateExpiryNotificationDetailsData(certExpiryNotificationDetailsMapper.fromAPIToModel(certificateExpiryNotificationDetails, Constants.CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE));
        }
        logger.debug("Mapped CAEntityData entity is {}", caEntityData);

        return (E) caEntityData;
    }

    /**
     * Method to convert CAEntityData to CertificateAuthority. All the fields of CertificateAuthority are set based on embeddedObjectsRequired .
     * 
     * @param caEntityData
     *            The caEntityData to convert.
     * @param embeddedObjectsRequired
     *            Attribute to define if embedded objects are required or not
     * @return mapped CertificateAuthority object
     * @throws InvalidEntityAttributeException
     */
    private CertificateAuthority toCertAuthAPIModel(final CAEntityData caEntityData, final boolean embeddedObjectsRequired)
            throws InvalidEntityAttributeException {
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

        if (embeddedObjectsRequired) {
            try {
                final Set<CertificateData> certificates = certificateAuthorityData.getCertificateDatas();
                if (certificates != null) {
                    final Iterator<CertificateData> it = certificates.iterator();
                    final List<Certificate> inactiveCertificates = new ArrayList<Certificate>();

                    while (it.hasNext()) {
                        final CertificateData certificateData = it.next();
                        if (certificateData.getStatus().intValue() == CertificateStatus.ACTIVE.getId()) {

                            certificateAuthority.setActiveCertificate(toObjectModel(certificateData));

                        } else {
                            inactiveCertificates.add(toObjectModel(certificateData));
                        }
                    }

                    certificateAuthority.setInActiveCertificates(inactiveCertificates);
                }

                final List<CRLInfo> crlList = new ArrayList<CRLInfo>();
                final Set<CRLInfoData> crlInfo = caEntityData.getCertificateAuthorityData().getcRLDatas();
                if (crlInfo != null) {

                    for (final CRLInfoData crlData : crlInfo) {
                        crlList.add(crlMapper.toAPIFromModel(crlData));
                    }

                }

                certificateAuthority.setCrlInfo(crlList);
                certificateAuthority.setCrlGenerationInfo(cRLGenerationInfoMapper.toAPIFromModel(certificateAuthorityData.getCrlGenerationInfo()));

            } catch (final AlgorithmException | CertificateException | InvalidCRLGenerationInfoException | IOException e){
                throw new InvalidEntityAttributeException(ErrorMessages.INTERNAL_ERROR + e.getMessage(), e);
            }

            certificateAuthority.setIssuer(toCertAuthAPIModelWithoutIssuer(caEntityData.getCertificateAuthorityData().getIssuer()));
        }

        return certificateAuthority;
    }

    protected CertificateAuthorityData fromAPIToModelCertAuth(final CertificateAuthority certificateAuthority) throws CRLServiceException {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setName(certificateAuthority.getName());
        certificateAuthorityData.setSubjectDN(fromSubject(certificateAuthority.getSubject()));
        certificateAuthorityData.setSubjectAltName(fromSubjectAltName(certificateAuthority.getSubjectAltName()));
        certificateAuthorityData.setRootCA(certificateAuthority.isRootCA());
        if (certificateAuthority.getStatus() != null) {
            certificateAuthorityData.setStatus(certificateAuthority.getStatus().getId());
        }
        if (certificateAuthority.getCrlGenerationInfo() != null) {
            certificateAuthorityData.setCrlGenerationInfo(cRLGenerationInfoMapper.toModelFromAPI(certificateAuthority.getCrlGenerationInfo()));
        }
        certificateAuthorityData.setcRLDatas(setCRLInfoList(certificateAuthority.getCrlInfo()));
        certificateAuthorityData.setPublishToCDPS(certificateAuthority.isPublishToCDPS());

        return certificateAuthorityData;
    }

    private boolean isRootCA(final EntityProfileData entityProfileData) {
        return entityProfileData.getCertificateProfileData().getIssuerData() == null ? true : false;
    }

    private Set<CRLInfoData> setCRLInfoList(final List<CRLInfo> crlInfoList) throws CertificateServiceException, CRLServiceException {
        final HashSet<CRLInfoData> crlInfoDataSet = new HashSet<CRLInfoData>();
        if (crlInfoList == null) {
            return null;
        }

        for (final CRLInfo crlInfo : crlInfoList) {
            crlInfoDataSet.add(crlMapper.fromAPIToModel(crlInfo, OperationType.UPDATE));
        }
        return crlInfoDataSet;
    }

    /**
     * This method converts given JPA model to API model but does not include certificates of that entity.
     *
     * @param entityData
     *            The entityData to convert.
     * @return caEntity object.
     * @throws CAEntityNotInternalException
     *             Thrown when given CA Entity exists but it's an external CA.
     * @throws CANotFoundException
     *             Thrown when given CA Entity is not Found.
     * @throws InvalidProfileAttributeException
     *             Thrown when the given profile attribute is invalid.
     */
    @SuppressWarnings("unchecked")
    public <T, E> T toAPIFromModelWithoutCertificates(final E entityData) throws CAEntityNotInternalException, CANotFoundException, InvalidProfileAttributeException {

        final CAEntityData caEntityData = (CAEntityData) entityData;

        logger.debug("Mapping CAEntityData entity {} to CAEntity domain model.", caEntityData.getId());
        final CertificateAuthority certificateAuthority = toCertAuthAPIModelWithoutIssuer(caEntityData);

        if (caEntityData.isExternalCA()) {
            throw new CAEntityNotInternalException(ProfileServiceErrorCodes.CA_ENTITY_IS_EXTERNAL);
        }
        final CAEntity caEntity = new CAEntity();

        caEntity.setCertificateAuthority(certificateAuthority);

        if (caEntityData.getKeyGenerationAlgorithm() != null) {
            caEntity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(caEntityData.getKeyGenerationAlgorithm()));
        }

        caEntity.setEntityProfile((EntityProfile) entityProfileMapper.toAPIFromModel(caEntityData.getEntityProfileData()));
        caEntity.setPublishCertificatetoTDPS(caEntityData.isPublishCertificatetoTDPS());

        logger.debug("Mapped CAEntity domain model is {}", caEntity);

        return (T) caEntity;
    }

    /**
     * Maps the CAEntity JPA model to its corresponding API model. This method maps the name, subject and status of the caEntity.
     *
     * @param dataModel
     *            CAEntityData Object which should be converted to API model CAEntity
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping CAEntity
     */
    @SuppressWarnings("unchecked")
    public <T, E> T toAPIFromModelForSummary(final E dataModel) throws InvalidEntityAttributeException {

        final CAEntityData caEntityData = (CAEntityData) dataModel;

        logger.debug("Mapping CAEntityData entity to CAEntity domain model for {}", caEntityData.getCertificateAuthorityData().getName());

        final CAEntity entity = new CAEntity();
        final CertificateAuthority ca = new CertificateAuthority();
        final CertificateAuthorityData caData = caEntityData.getCertificateAuthorityData();

        ca.setId(caEntityData.getId());
        ca.setName(caData.getName());
        ca.setSubject(toSubject(caData.getSubjectDN()));
        ca.setSubjectAltName(toSubjectAltName(caData.getSubjectAltName()));
        ca.setRootCA(caData.isRootCA());
        ca.setStatus(CAStatus.getStatus(caData.getStatus()));
        ca.setPublishToCDPS(caData.isPublishToCDPS());

        entity.setCertificateAuthority(ca);

        return (T) entity;
    }

}
