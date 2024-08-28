/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CertificateExpiryNotificationDetailsMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.EntityProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.AbstractModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CRLInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

@RequestScoped
@EntityQualifier(EntityType.CA_ENTITY)
public class CAEntityModelMapper extends AbstractModelMapperv1 {

    @Inject
    @ProfileQualifier(ProfileType.ENTITY_PROFILE)
    EntityProfileMapper entityProfileMapper;

    @Inject
    CRLInfoMapper crlMapper;

    @Inject
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    @SuppressWarnings("unchecked")
    @Override
    public <T, E> T toApi(final E entityData, final MappingDepth depth) throws CAEntityNotInternalException, InvalidEntityAttributeException {
        final CAEntityData caEntityData = (CAEntityData) entityData;
        CertificateAuthority certificateAuthority = null;
        switch (depth) {
        case LEVEL_0:
            final CAEntity caEntity = new CAEntity();
            certificateAuthority = getCASummary(caEntityData);
            caEntity.setCertificateAuthority(certificateAuthority);
            return (T) caEntity;
        case LEVEL_1:
            return prepareCAEntityWithEmbeddedObjects(caEntityData, MappingDepth.LEVEL_1);
        case LEVEL_2:
            return prepareCAEntityWithEmbeddedObjects(caEntityData, MappingDepth.LEVEL_2);
        default:
            logger.debug("Unknown mapping depth");
            return null;
        }

    }

    @SuppressWarnings("unchecked")
    private <T, E> T prepareCAEntityWithEmbeddedObjects(final E entityData, final MappingDepth mappingDepth) {

        final CAEntityData caEntityData = (CAEntityData) entityData;

        logger.debug("Mapping CAEntityData entity {} to CAEntity domain model.", caEntityData.getId());

        final CertificateAuthority certificateAuthority = getCASummary(caEntityData);

        if (caEntityData.isExternalCA()) {
            throw new CAEntityNotInternalException(ProfileServiceErrorCodes.CA_ENTITY_IS_EXTERNAL);
        }

        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);
        addCertsToCertAuth(caEntityData, caEntity.getCertificateAuthority(), mappingDepth);



        if (caEntityData.getKeyGenerationAlgorithm() != null) {
            caEntity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(caEntityData.getKeyGenerationAlgorithm()));
        }

        caEntity.setEntityProfile((EntityProfile) entityProfileMapper.toAPIFromModel(caEntityData.getEntityProfileData()));
        caEntity.setPublishCertificatetoTDPS(caEntityData.isPublishCertificatetoTDPS());
        final Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet = caEntityData
                .getCertificateExpiryNotificationDetailsData();
        if (!ValidationUtils.isNullOrEmpty(certExpiryNotificationDetailsDataSet)) {
            caEntity.setCertificateExpiryNotificationDetails(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet));
        }
        logger.debug("Mapped CAEntity domain model is {}", caEntity);
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
    public <T, E> E fromApi(final T apiModel) throws EntityServiceException {
        final CAEntityData caEntityData = new CAEntityData();
        final CAEntity caEntity = (CAEntity) apiModel;
        logger.debug("Mapping CAEntity domain model {} to CAEntityData entity.", caEntity);

        final CertificateAuthority certificateAuthority = caEntity.getCertificateAuthority();

        caEntityData.setId(certificateAuthority.getId());
        caEntityData.setPublishCertificatetoTDPS(caEntity.isPublishCertificatetoTDPS());
        try {
            final EntityProfileData entityProfileData = populateEntityProfileData(caEntity.getEntityProfile().getName());
            caEntityData.setEntityProfileData(entityProfileData);
            if (caEntity.getKeyGenerationAlgorithm() != null) {
                caEntityData.setKeyGenerationAlgorithm(populateKeyGenerationAlgorithm(caEntity.getKeyGenerationAlgorithm().getName(), caEntity
                        .getKeyGenerationAlgorithm().getKeySize()));
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
            caEntityData.setCertificateExpiryNotificationDetailsData(certExpiryNotificationDetailsMapper.fromAPIToModel(
                    certificateExpiryNotificationDetails, Constants.CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE));
        }
        logger.debug("Mapped CAEntityData entity is {}", caEntityData);

        return (E) caEntityData;
    }

    /**
     * Method to convert CAEntityData to CertificateAuthority. All the fields of CertificateAuthority are set based on embeddedObjectsRequired .
     *
     * @param caEntityData
     *            The caEntityData to convert.
     * @param certificateAuthority
     *            The certificateAuthority to add certificates
     * @throws InvalidEntityAttributeException
     */
    private void addCertsToCertAuth(final CAEntityData caEntityData, final CertificateAuthority certificateAuthority, final MappingDepth mappingDepth)
            throws InvalidEntityAttributeException {

        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

        try {
            final Set<CertificateData> certificates = certificateAuthorityData.getCertificateDatas();
            if (certificates != null) {
                final Iterator<CertificateData> it = certificates.iterator();
                final List<Certificate> inactiveCertificates = new ArrayList<>();

                while (it.hasNext()) {
                    final CertificateData certificateData = it.next();
                    if (certificateData.getStatus().intValue() == CertificateStatus.ACTIVE.getId()) {
                        certificateAuthority.setActiveCertificate(toApi(certificateData, mappingDepth));
                    } else {
                        inactiveCertificates.add(toApi(certificateData, mappingDepth));
                    }
                }

                certificateAuthority.setInActiveCertificates(inactiveCertificates);
            }

            final List<CRLInfo> crlList = new ArrayList<>();
            final Set<CRLInfoData> crlInfo = caEntityData.getCertificateAuthorityData().getcRLDatas();
            if (crlInfo != null) {

                for (final CRLInfoData crlData : crlInfo) {
                    crlList.add(crlMapper.toAPIFromModel(crlData));
                }

            }

            certificateAuthority.setCrlInfo(crlList);

        } catch (final AlgorithmException | InvalidCRLGenerationInfoException e) {
            throw new InvalidEntityAttributeException(ErrorMessages.INTERNAL_ERROR + e.getMessage(), e);
        }
        certificateAuthority.setIssuer(getCASummary(caEntityData.getCertificateAuthorityData().getIssuer()));
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
        final boolean rootCA = true;
        if (entityProfileData.getCertificateProfileData().getIssuerData() == null) {
            return rootCA;
        } else {
            return false;
        }
    }

    private Set<CRLInfoData> setCRLInfoList(final List<CRLInfo> crlInfoList) throws CertificateServiceException, CRLServiceException {
        final HashSet<CRLInfoData> crlInfoDataSet = new HashSet<>();
        if (crlInfoList == null) {
            return crlInfoDataSet;
        }

        for (final CRLInfo crlInfo : crlInfoList) {
            crlInfoDataSet.add(crlMapper.fromAPIToModel(crlInfo, OperationType.UPDATE));
        }
        return crlInfoDataSet;
    }


    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1#getEntityv1(com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData)
     */
    @Override
    public <T> T getEntitySummaryWithCertificates(final EntityData entityData) throws InvalidEntityAttributeException {
        // TODO Auto-generated method stub
        return null;
    }
}
