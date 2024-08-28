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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.utils.CertificateServiceExceptionUtil;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate.ExtCertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AbstractEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;

/**
 * This class is used to consist of all methods required for updating/ retrieving data from Manager DB.
 * 
 * @author tcsdemi
 * 
 */
public class TDPSPersistenceHandler {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    ExtCertificateModelMapper extCertificateModelMapper;

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    /**
     * This will retrieve active and inactive certificates for Entities which have published flag as true.
     * 
     * @param entityType
     *            Retrieve the certificates which matches the given entityType.
     * 
     * @returns List of published certificates which are active or inactive.
     * 
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */

    public Map<String, List<Certificate>> getPublishedCertificatesByType(final EntityType entityType) throws CertificateException, IOException, PersistenceException {
        return getPublishedCertificates(entityType, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    /**
     * This will retrieve all the certificates for Entities which have published flag as true.
     * 
     * @param entityType
     *            Retrieve the certificates which matches the given entityType.
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     * 
     * @returns List of published certificates which are active or inactive.
     * 
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */

    public Map<String, List<Certificate>> getPublishedCertificates(final EntityType entityType, final CertificateStatus... certificateStatuses) throws CertificateException, IOException,
            InvalidEntityException, PersistenceException {
        Map<String, List<Certificate>> certificateInfoMap = new HashMap<String, List<Certificate>>();

        switch (entityType) {
        case CA_ENTITY:
            certificateInfoMap = getCAEntityTDPSCertificates(true, certificateStatuses);
            break;

        case ENTITY:
            certificateInfoMap = getEntityTDPSCertificates(true, certificateStatuses);
            break;

        default:
            throw new InvalidEntityException(ProfileServiceErrorCodes.UNKNOWN_ENTITYTYPE);
        }

        return certificateInfoMap;
    }

    /**
     * This will retrieve active and inactive certificates for CA which have published flag as true.
     *
     * @returns a Map with entityName and List of certificates which are active or inactive.
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */
    public Map<String, List<Certificate>> getPublishableCACertificates() throws CertificateException, IOException, PersistenceException {
        return getCAEntityTDPSCertificates(false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    /**
     * This will retrieve all the certificates for CA which have published flag as true.
     * 
     * @param onlyPublishedCertsRequired
     *            This flag determines which certificates have to be returned. If the value is true, then only the Certificates that are published to TDPS are returned. If the value is false, all the
     *            ACTIVE and INACTIVE certificates of all the entities that can be published to TDPS are returned.
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     * 
     * @returns a Map with entityName and List of certificates which are active or inactive.
     *
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */
    public Map<String, List<Certificate>> getCAEntityTDPSCertificates(final boolean onlyPublishedCertsRequired, final CertificateStatus... certificateStatuses) throws CertificateException,
            IOException, PersistenceException {
        logger.debug("Fetching publishedCertificates for CA entities");
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("publishCertificatetoTDPS", true);

        final List<CAEntityData> caEntityDatas = persistenceManager.findEntitiesWhere(CAEntityData.class, parameters);
        final Map<String, List<Certificate>> certificateInfoMap = getEntityMap(onlyPublishedCertsRequired, EntityType.CA_ENTITY, caEntityDatas, certificateStatuses);
        logger.debug("Fetching publishedCertificates for CA entities Finished");
        return certificateInfoMap;
    }

    /**
     * This will retrieve a Map with entityName and certificates(Active/Inactive) for Entities which have published flag as true.
     *
     * @returns a Map with entityName and List of certificates which are active or inactive.
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */
    public Map<String, List<Certificate>> getPublishableEntityCertificates() throws CertificateException, IOException, PersistenceException {
        return getEntityTDPSCertificates(false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    /**
     * This will retrieve all the certificates for Entities which have published flag as true.
     *
     * @param onlyPublishedCertsRequired
     *            This flag determines which certificates have to be returned. If the value is true, then only the Certificates that are published to TDPS are returned. If the value is false, all the
     *            ACTIVE and INACTIVE certificates of all the entities that can be published to TDPS are returned.
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     * 
     * @returns a Map with entityName and List of certificates which are active or inactive.
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     */
    public Map<String, List<Certificate>> getEntityTDPSCertificates(final boolean onlyPublishedCertsRequired, final CertificateStatus... certificateStatuses) throws CertificateException, IOException,
            PersistenceException {
        logger.debug("Fetching publishedCertificates for End entities");
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("publishCertificatetoTDPS", true);
        parameters.put("entityInfoData.status", 2);

        final List<EntityData> entityDatas = persistenceManager.findEntitiesWhere(EntityData.class, parameters);
        final Map<String, List<Certificate>> certificateInfoMap = getEntityMap(onlyPublishedCertsRequired, EntityType.ENTITY, entityDatas, certificateStatuses);
        logger.debug("Fetched publishedCertificates for end entities ");
        return certificateInfoMap;
    }

    /**
     * This method is used to update certificate data table with the publishedToTDPS flag depending on the acknowledgement status.
     * 
     * @param entityType
     *            is the type of entity which can CA_Entity or Entity.
     * @param entityName
     *            is the name of entity which is present in the PKI system.
     * @param issuerName
     *            is the name of the issuerName who issued certificate to entityName.
     * @param serialNumber
     *            is the serialNumber of the issued certificate.
     * @param publishedToTDPS
     *            is a boolean which will be true in case publishCertificate acknowledgement is a success and false in case unpublishCertificate acknowledgement is a success.
     * 
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     * @throws EntityNotFoundException
     *             is thrown in case entity is not found.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */
    public void updateCertificateData(final EntityType entityType, final String entityName, final String issuerName, final String serialNumber, final boolean publishedToTDPS)
            throws CertificateException, EntityNotFoundException, IOException, PersistenceException {
        logger.debug("Updating CertificateData for entity {}", entityName);
        final CertificateData certificateData = getCertificateData(entityType, entityName, issuerName, serialNumber);
        if (certificateData != null) {
            certificateData.setPublishedToTDPS(publishedToTDPS);
        }
        persistenceManager.updateEntity(certificateData);
        logger.debug("Updated published to tdps flag in certificateData for entity {}", entityName);
    }

    /**
     * This method is publish flag for the entity to convey whether this entity's certificates need to be published to TDPS
     *
     * @param entityName
     *            is the name of entity which is present in the PKI system.
     * @param entityType
     *            is the type of entity which can CA_Entity or Entity.
     * @param publishCertificateToTDPSFlag
     *            if true then certificate is to be published to or unpublished from TDPS.
     * @throws CANotFoundException
     *             is thrown when the given CA entity is not found.
     * @throws EntityNotFoundException
     *             is thrown when the given End entity is not found.
     * @throws EntityServiceException
     *             is thrown when internal db error occurs while getting EntityData.
     * @throws PersistenceException
     *             is thrown in case of an internal db error.
     */
    public void updateEntityData(final String entityName, final EntityType entityType, final boolean publishCertificateToTDPSFlag) throws CANotFoundException, EntityNotFoundException,
            EntityServiceException, PersistenceException {
        logger.debug("Updating entityData for TDPS publish flag for entity {}", entityName);
        final AbstractEntityData abstractEntityData = getEntityData(entityType, entityName);

        if (abstractEntityData != null) {
            abstractEntityData.setPublishCertificatetoTDPS(publishCertificateToTDPSFlag);
        }

        persistenceManager.updateEntity(abstractEntityData);
        logger.debug("Updated publish to tdps flag in entityData for entity {}", entityName);
    }

    private CertificateData getCertificateData(final EntityType entityType, final String entityName, final String issuerName, final String serialNumber) throws EntityNotFoundException,
            PersistenceException, CertificateException, IOException {
        CertificateData certificateData = null;

        switch (entityType) {
        case ENTITY: {
            certificateData = getEntityCertificateData(entityName, issuerName, serialNumber);
            break;
        }
        case CA_ENTITY: {
            final CAEntityData caEntityData = caCertificatePersistenceHelper.getCAEntity(entityName);
            if (caEntityData.isExternalCA()) {
                certificateData = getExtCACertificateData(entityName, issuerName, serialNumber);
            } else {
                certificateData = getCACertificateData(entityName, issuerName, serialNumber);
            }
            break;
        }
        }
        return certificateData;
    }

    private CertificateData getExtCACertificateData(final String entityName, final String issuerName, final String serialNumber) throws EntityNotFoundException, PersistenceException {
        CertificateData certificateDataToBeUpated = null;

        final List<CertificateData> certificateDatas = extCACertificatePersistanceHandler.getCertificateDatasForExtCA(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);

        for (final CertificateData certificateData : certificateDatas) {
            if (certificateData.getIssuerCA().getCertificateAuthorityData().getName().equals(issuerName) && certificateData.getSerialNumber().equals(serialNumber)) {
                certificateDataToBeUpated = certificateData;
            }
        }

        return certificateDataToBeUpated;
    }

    private CertificateData getCACertificateData(final String entityName, final String issuerName, final String serialNumber) throws EntityNotFoundException, PersistenceException {
        CertificateData certificateDataToBeUpated = null;

        final List<CertificateData> certificateDatas = caCertificatePersistenceHelper.getCertificateDatas(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE, CertificateStatus.REVOKED);

        for (final CertificateData certificateData : certificateDatas) {
            if (certificateData.getIssuerCA().getCertificateAuthorityData().getName().equals(issuerName) && certificateData.getSerialNumber().equals(serialNumber)) {
                certificateDataToBeUpated = certificateData;
            }
        }

        return certificateDataToBeUpated;
    }

    private CertificateData getEntityCertificateData(final String entityName, final String issuerName, final String serialNumber) throws EntityNotFoundException, PersistenceException,
            CertificateException, IOException {
        CertificateData certificateDataToBeUpated = null;

        final EntityData entityData = entityCertificatePersistenceHelper.getEntityData(entityName);
        final Set<CertificateData> certificateDatas = entityData.getEntityInfoData().getCertificateDatas();

        for (final CertificateData certificateData : certificateDatas) {
            if (certificateData.getIssuerCA().getCertificateAuthorityData().getName().equals(issuerName) && certificateData.getSerialNumber().equals(serialNumber)) {
                certificateDataToBeUpated = certificateData;
            }
        }

        return certificateDataToBeUpated;
    }

    private AbstractEntityData getEntityData(final EntityType entityType, final String entityName) throws CANotFoundException, EntityNotFoundException, EntityServiceException {
        AbstractEntityData abstractEntityData = null;

        switch (entityType) {
        case CA_ENTITY: {
            abstractEntityData = caCertificatePersistenceHelper.getCAEntity(entityName);
            break;
        }
        case ENTITY: {
            abstractEntityData = entityCertificatePersistenceHelper.getEntityData(entityName);
            break;
        }
        }
        return abstractEntityData;
    }

    private Map<String, List<Certificate>> getEntityMap(final boolean onlyPublishedCertsRequired, final EntityType entityType, final List<? extends AbstractEntityData> abstractEntityDatas,
            final CertificateStatus... certificateStatuses) throws CertificateException, IOException {
        final Map<String, List<Certificate>> certificateInfoMap = new HashMap<String, List<Certificate>>();
        List<CertificateData> certificateDatas = null;

        if (ValidationUtils.isNullOrEmpty(abstractEntityDatas)) {
            return certificateInfoMap;
        }

        for (final AbstractEntityData eachAbstractEntityData : abstractEntityDatas) {

            final String entityName = ((entityType == EntityType.CA_ENTITY) ? ((CAEntityData) eachAbstractEntityData).getCertificateAuthorityData().getName() : ((EntityData) eachAbstractEntityData)
                    .getEntityInfoData().getName());

            if ((entityType == EntityType.CA_ENTITY) && ((CAEntityData) eachAbstractEntityData).isExternalCA()) {
                certificateDatas = extCACertificatePersistanceHandler.getCertificateDatasForExtCA(entityName, certificateStatuses);
            } else {
                certificateDatas = getCertificateDatas(entityType, entityName, certificateStatuses);
            }

            Certificate certificate = null;

            if (!ValidationUtils.isNullOrEmpty(certificateDatas)) {

                final List<Certificate> certificates = new ArrayList<Certificate>();

                for (final CertificateData certificateData : certificateDatas) {
                    if (certificateData.isPublishedToTDPS() && onlyPublishedCertsRequired) {
                        certificate = toCertificate(entityType, eachAbstractEntityData, certificateData);
                        certificates.add(certificate);
                    }
                    if (!onlyPublishedCertsRequired) {
                        certificate = toCertificate(entityType, eachAbstractEntityData, certificateData);
                        if (certificate.getIssuer() != null) {
                            certificates.add(certificate);
                        }
                    }

                }
                certificateInfoMap.put(entityName, certificates);
            }
        }

        return certificateInfoMap;
    }

    private Certificate toCertificate(final EntityType entityType, final AbstractEntityData eachAbstractEntityData, final CertificateData certificateData) throws CertificateException, IOException {
        Certificate certificate = null;
        if ((entityType == EntityType.CA_ENTITY) && ((CAEntityData) eachAbstractEntityData).isExternalCA()) {
            certificate = extCertificateModelMapper.toCertificate(certificateData);
        } else {
            certificate = certificateModelMapper.toCertificateForTDPSInfo(certificateData);
        }
        return certificate;
    }

    /**
     * This method will return the list of certificates data for a given entityType, entity Name and status.
     *
     * @param entityType
     *            Retrieve the certificates which matches the given entityType.
     *
     * @param entityName
     *            Retrieve the certificates which matches the given entityName.
     *
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     *
     * @returns List of certificates data.
     *
     * @throws CANotFoundException
     *             is thrown when the given CA entity is not found in the system.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */
    public List<CertificateData> getCertificateDatas(final EntityType entityType, final String entityName, final CertificateStatus... certificateStatuses) throws CANotFoundException,
            PersistenceException {
        List<CertificateData> certificateDatas = null;

        switch (entityType) {
        case CA_ENTITY:
            final CAEntityData caEntityData = caCertificatePersistenceHelper.getCAEntity(entityName);
            if (caEntityData.isExternalCA()) {
                certificateDatas = extCACertificatePersistanceHandler.getCertificateDatasForExtCA(entityName, certificateStatuses);
            } else {
                certificateDatas = caCertificatePersistenceHelper.getCertificateDatas(entityName, certificateStatuses);
            }
            break;

        case ENTITY:
            certificateDatas = entityCertificatePersistenceHelper.getCertificateDatas(entityName, certificateStatuses);
            break;
        }
        return certificateDatas;
    }

    /**
     * This method will return the list of certificates data for a given entity
     * 
     * @param abstractEntity
     *            caentity/entity object
     * @return Certificate data Set
     * @throws CANotFoundException
     *             when the given CA entity is not found.
     * @throws EntityNotFoundException
     *             when the given end entity is not found
     * @throws CertificateServiceException
     *             when any internal db error occurs while retreiving the certificates
     */
    public Set<CertificateData> getCertificateDatas(final AbstractEntity abstractEntity) throws CANotFoundException, EntityNotFoundException, CertificateServiceException {
        Set<CertificateData> certificateDatas = null;
        try {
            switch (abstractEntity.getType()) {
            case ENTITY:

                final Entity entity = (Entity) abstractEntity;
                entity.getEntityInfo().getName();
                final EntityData entityData = entityCertificatePersistenceHelper.getEntityData(entity.getEntityInfo().getName());
                certificateDatas = entityData.getEntityInfoData().getCertificateDatas();
                break;

            case CA_ENTITY:
                final CAEntity caEntity = (CAEntity) abstractEntity;

                final CAEntityData caEntityData = caCertificatePersistenceHelper.getCAEntity(caEntity.getCertificateAuthority().getName());

                certificateDatas = caEntityData.getCertificateAuthorityData().getCertificateDatas();
                break;
            }
        } catch (EntityServiceException entityServiceException) {
            CertificateServiceExceptionUtil.throwCertificateServiceException(entityServiceException, entityServiceException.getMessage());
        }
        return certificateDatas;
    }

}
