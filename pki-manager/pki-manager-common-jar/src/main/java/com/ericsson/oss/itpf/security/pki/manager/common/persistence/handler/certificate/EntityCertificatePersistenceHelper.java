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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate.CertificateModelMapperV1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateRequestData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;

/**
 * Helper class for CRUD operations.
 *
 */
public class EntityCertificatePersistenceHelper {

    @Inject
    Logger logger;

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    CertificateModelMapperV1 certificateModelMapperV1;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    PersistenceManager persistenceManager;

    private static final String ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS = "select c from CertificateData c where c.status in(:status) and c.id in(select p.id from EntityData ec inner join ec.entityInfoData.certificateDatas p  WHERE ec.entityInfoData.name = :name) ORDER BY c.id DESC";
    private static final String ENTITY_NAMES_BY_STATUS = "SELECT ee.entityInfoData.name FROM EntityData ee WHERE ee.entityInfoData.status in (:status)";

    /**
     * Store the certificate of entity.
     *
     * @param entity
     *            The entity object.
     * @param certificate
     *            The certificate object to be saved.
     *
     * @throws CertificateEncodingException
     *             Thrown in case of any exception while encoding the certificate.
     * @throws PersistenceException
     *             Thrown in case of any problem occurs while doing database operations.
     */
    public void storeCertificate(final Entity entity, final CertificateGenerationInfo certGenInfo, final Certificate certificate) throws CertificateEncodingException, PersistenceException {

        final EntityData entityData = persistenceManager.findEntity(EntityData.class, entity.getEntityInfo().getId());

        makeActiveCertificateAsInActive(entityData);

        final CertificateData certificateData = createCertificateData(certificate);
        final CertificateData certData = storeCertificateData(certificateData);

        final CertificateGenerationInfoData certGenInfoData = persistenceManager.findEntity(CertificateGenerationInfoData.class, certGenInfo.getId());
        certGenInfoData.setCertificateData(certData);
        persistenceManager.updateEntity(certGenInfoData);

        updateEntityWithActiveCertificate(entityData, certData);
    }

    private void updateEntityWithActiveCertificate(final EntityData entityData, final CertificateData certData) throws CertificateEncodingException {

        entityData.getEntityInfoData().getCertificateDatas().add(certData);

        logger.info("count of entity certificates {} ", entityData.getEntityInfoData().getCertificateDatas().size());

        final int otpCount = entityData.getEntityInfoData().getOtpCount();
        if (otpCount > 0) {
            entityData.getEntityInfoData().setOtpCount(otpCount - 1);
        }
        entityData.getEntityInfoData().setStatus(EntityStatus.ACTIVE);

        persistenceManager.updateEntity(entityData);
    }

    /**
     * Store Certificate of entity.
     *
     * @param certificate
     *            The Certificate object.
     * @return CertificateData The CertificateData object.
     * @throws CertificateEncodingException
     *             Thrown in case of any exception while encoding the certificate.
     */
    private CertificateData storeCertificateData(final CertificateData certificateData) throws CertificateEncodingException {

        logger.debug("storing certificate of Entity whose serial number {}", certificateData.getSerialNumber());
        persistenceManager.createEntity(certificateData);

        final CertificateData certData = persistenceManager.findEntity(CertificateData.class, certificateData.getId());
        logger.info("Saved Certificate! its id is {}, serial number is {}", certData.getId(), certData.getSerialNumber());
        return certData;
    }

    private void makeActiveCertificateAsInActive(final EntityData entityData) throws PersistenceException{

        final List<CertificateData> certificateDatas = getCertificateDatas(entityData.getEntityInfoData().getName(), CertificateStatus.ACTIVE);

        for (final CertificateData certificateData : certificateDatas) {
            if (certificateData.getStatus().intValue() == CertificateStatus.ACTIVE.getId()) {
                certificateData.setStatus(CertificateStatus.INACTIVE.getId());
                final EntityData enData = persistenceManager.updateEntity(entityData);
                persistenceManager.refresh(enData);
                break;
            }
        }
    }

    /**
     * Create the Certificate Data
     *
     * @param certificate
     *            The certificate object.
     * @return CertificateData Object.
     *
     * @throws CertificateEncodingException
     *             Throws in case of error occurred while encoding the data.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    private CertificateData createCertificateData(final Certificate certificate) throws CertificateEncodingException, PersistenceException {

        final CertificateData certificateData = certificateModelMapper.fromObjectModel(certificate);
        logger.debug("storing certificate of Entity whose serial number {}", certificateData.getSerialNumber());
        return certificateData;
    }

    /**
     * Get the certificates of given entity.
     *
     * @param entityName
     *            The entity name.
     * @param certificateStatuses
     *            The Certificate status.
     * @return List of certificates. Retrieve the certificates which matches the given statuses.
     * @throws CertificateException
     *             Throws in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Throws in the event of corrupted data or an incorrect structure of certificate.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */

    public List<Certificate> getCertificates(final String entityName, final MappingDepth depth, final CertificateStatus... certificateStatuses) throws CertificateException, IOException, PersistenceException {

        final List<CertificateData> certificateDatas = getCertificateDatas(entityName, certificateStatuses);

        if (!ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return certificateModelMapperV1.toApi(certificateDatas, depth);
        }
        return null;
    }

    /**
     * Get the certificates of given entity.
     *
     * @param entityName
     *            The entity name.
     * @param certificateStatuses
     *            The Certificate status.
     * @param embeddedObjectsRequired
     *            This attribute will specify if EmbeddedObjects inside Certificate object are required
     * @return List of certificates. Retrieve the certificates which matches the given statuses.
     * @throws CertificateException
     *             Throws in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Throws in the event of corrupted data or an incorrect structure of certificate.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public List<Certificate> getCertificates(final String entityName, final boolean embeddedObjectsRequired, final CertificateStatus... certificateStatuses) throws CertificateException, IOException, PersistenceException {

        final List<CertificateData> certificateDatas = getCertificateDatas(entityName, certificateStatuses);

        if (!ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return certificateModelMapper.toObjectModel(certificateDatas, embeddedObjectsRequired);
        }
        return null;
    }

    /**
     * Gets the certificates by the given serialNumber.
     *
     * @param serialNumber
     *            The serialNumber with which the certificates to be obtained.
     * @return List of certificates. Retrieve the certificates which matches the given serialNumber.
     * @throws CertificateException
     *             Throws in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Throws in the event of corrupted data or an incorrect structure of certificate.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public List<Certificate> getCertificatesBySerialNumber(final String serialNumber) throws CertificateException, IOException, PersistenceException {

        final Map<String, Object> attributes = new HashMap<>();
        attributes.put("serialNumber", serialNumber);
        final List<CertificateData> certificateDatas = persistenceManager.findEntitiesByAttributes(CertificateData.class, attributes);

        if (!ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return certificateModelMapper.toObjectModel(certificateDatas);
        }
        return Collections.emptyList();
    }

    /**
     * This method will return the list of certificates data for a given entity Name and status.
     *
     * @param entityName
     *            The entity name.
     * @param certificateStatuses
     *            The Certificate status.
     * @return List of certificate data objects.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */

    public List<CertificateData> getCertificateDatas(final String entityName, final CertificateStatus... certificateStatuses) throws PersistenceException {
        final List<Integer> certificateStatusIds = new ArrayList<Integer>();
        for (final CertificateStatus certificateStatus : certificateStatuses) {
            certificateStatusIds.add(certificateStatus.getId());
        }

        final Query query = persistenceManager.getEntityManager().createQuery(ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS);

        query.setParameter("name", entityName);
        query.setParameter("status", certificateStatusIds);

        final List<CertificateData> certificateDatas = query.getResultList();

        return certificateDatas;
    }

    /**
     * Get EntityData of given entity.
     *
     * @param entityName
     *            The entity name.
     * @return entityData Object
     *
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists
     * @throws EntityServiceException
     *             Thrown in case of any problem occurs while doing database operations.
     */
    public EntityData getEntityData(final String entityName) throws EntityNotFoundException, EntityServiceException {
        EntityData entityData = null;
        try {
            entityData = persistenceManager.findEntityByName(EntityData.class, entityName, Constants.ENTITY_NAME_PATH);
        } catch (PersistenceException persistenceException) {
            logger.error(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ENTITY + persistenceException);
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ENTITY, persistenceException);
        }
        if (entityData == null) {
            logger.error("Entity {}  not found", entityName);
            throw new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND + ": " + entityName);
        }

        return entityData;

    }

    /**
     * Store the certificateGenerationInfo Object.
     *
     * @param certificateGenerationInfo
     *            The CertificateGenerationInfo Object.
     * @throws IOException
     *             Thrown in case of any exception occurs while converting certificateRequest into byte array.
     * @throws PersistenceException
     *             Thrown in case of internal error while storing CertificateGenerationInfo.
     */
    public void storeCertificateGenerateInfo(final CertificateGenerationInfo certificateGenerationInfo) throws IOException, PersistenceException {

        final CertificateGenerationInfoData certificateGenerationInfoData = certificateModelMapper.toCertificateGenerationInfoData(certificateGenerationInfo);
        persistenceManager.createEntity(certificateGenerationInfoData);

        final CertificateRequestData certificateRequestData = certificateModelMapper.toCertificateRequestData(certificateGenerationInfo.getCertificateRequest());
        persistenceManager.createEntity(certificateRequestData);
        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);

        persistenceManager.updateEntity(certificateGenerationInfoData);
        certificateGenerationInfo.setId(certificateGenerationInfoData.getId());
    }

    /**
     * This method will return the list of entity certificates which are expired and has to be unpublished.
     * 
     * @return Map of entity name and its list of certificates.
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurs.
     */
    public Map<String, List<Certificate>> getExpiredEntityCertificatesToUnpublish() throws CertificateServiceException {
        final Map<String, List<Certificate>> entityCertsMap = new HashMap<String, List<Certificate>>();
        try {
            final List<String> entityNames = getAllEntityNameByStatus(EntityStatus.ACTIVE, EntityStatus.INACTIVE);
            for (final String entityName : entityNames) {

                final List<CertificateData> certificateDatas = getCertificateDatas(entityName, CertificateStatus.EXPIRED);
                if (certificateDatas != null) {
                    final List<CertificateData> certsToBeAdded = new ArrayList<CertificateData>();
                    for (final CertificateData certificateData : certificateDatas) {
                        if (certificateData.isPublishedToTDPS()) {
                            certsToBeAdded.add(certificateData);
                        }
                    }
                    if (!certsToBeAdded.isEmpty()) {
                        entityCertsMap.put(entityName, certificateModelMapper.toObjectModel(certsToBeAdded));
                    }
                }
            }
        } catch (CertificateException | PersistenceException | IOException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, exception);
        }
        return entityCertsMap;
    }

    /**
     * This method will return the list of Entity names of the entities with the given Entity statuses.
     *
     * @param entityStatuses
     *            Status of the Entity by which the Entity names are to be fetched.
     * @return List of Entity names.
     * @throws PersistenceException
     *             Thrown in case any database issue occurs.
     */
    @SuppressWarnings("unchecked")
    public List<String> getAllEntityNameByStatus(final EntityStatus... entityStatuses) throws PersistenceException {
        List<String> EntityNames = null;
        final List<Integer> entityStatusIds = new ArrayList<>();
        for(EntityStatus entityStatus : entityStatuses) {
             entityStatusIds.add(entityStatus.getId());
        }
        final Query query = persistenceManager.getEntityManager().createQuery(ENTITY_NAMES_BY_STATUS);
        query.setParameter("status", entityStatusIds);
        EntityNames = query.getResultList();
        return EntityNames;
    }
}
