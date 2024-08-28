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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.core.common.constants.EntityManagementErrorCodes;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.*;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

public class CAEntityPersistenceHandler {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    @Inject
    CertificateAuthorityModelMapper cAEntityMapper;

    private static final String updateCAEntityStatusToInactiveNativeQuery = "update certificate_authority SET status_id=3 where id not in (select distinct ca_cert.ca_id from ca_certificate ca_cert where ca_cert.certificate_id in (select cert.id from certificate cert where cert.status_id in (1,4))) and status_id = 2";

    /**
     * Maps API model to JPA entity and persists in the database.
     *
     * @param certificateAuthority
     *            object to be mapped with JPA entity and to be persisted in database.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case JPA entity already exists in the database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void persistCA(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        try {
            final CertificateAuthorityData certificateAuthorityData = cAEntityMapper.fromAPIModel(certificateAuthority, OperationType.CREATE);
            persistenceManager.createEntity(certificateAuthorityData);

        } catch (final EntityExistsException entityExistsException) {
            logger.error("Entity Already Exists {}", entityExistsException.getMessage());
            throw new CoreEntityAlreadyExistsException(EntityManagementErrorCodes.ENTITY_ALREADY_EXISTS, entityExistsException);
        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Inactive Error in creating entity {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }
        logger.debug("Created {}", certificateAuthority);
    }

    /**
     * Maps API model to JPA entity and updates the same in the database.
     *
     * @param certificateAuthority
     *            object to be mapped with JPA entity and to be updated in database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws CRLServiceException
     *             in case of db errors for CRL operations
     */
    public void updateCA(final CertificateAuthority certificateAuthority) throws CoreEntityServiceException {

        try {
            final CertificateAuthorityData certificateAuthorityData = cAEntityMapper.fromAPIModel(certificateAuthority, OperationType.UPDATE);
            persistenceManager.updateEntity(certificateAuthorityData);

        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in updating Entity {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }
        logger.debug("Updated {}", certificateAuthority);
    }

    /**
     * Get CA Entity Certificates and update certificate status to EXPIRED/INACTIVE into DataBase.
     *
     * @param certificateAuthorityData
     *            object to be used to get CertificateData
     * @param caStatus
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void updateCertificateStatus(final CertificateAuthorityData certificateAuthorityData, final CAStatus caStatus) throws CoreEntityServiceException {

        try {
            final Set<CertificateData> certificateDatasSet = certificateAuthorityData.getCertificateDatas();
            if (!ValidationUtils.isNullOrEmpty(certificateDatasSet)) {
                final List<CertificateData> certificateDatasList = new ArrayList<CertificateData>(certificateDatasSet);
                final CertificateData certificateData = Collections.max(certificateDatasList, new ComparatorUtil());
                if (caStatus == CAStatus.ACTIVE && certificateAuthorityData.getStatus() == CAStatus.INACTIVE && certificateData.getStatus() == CertificateStatus.INACTIVE) {
                    if (certificateData.getNotAfter().compareTo(new Date()) < 0) {
                        certificateData.setStatus(CertificateStatus.EXPIRED);
                        persistenceManager.updateEntity(certificateData);
                    }
                } else if (caStatus == CAStatus.INACTIVE && certificateAuthorityData.getStatus() == CAStatus.ACTIVE && certificateData.getStatus() == CertificateStatus.ACTIVE) {
                    certificateData.setStatus(CertificateStatus.INACTIVE);
                    persistenceManager.updateEntity(certificateData);
                }
            }
        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in Updated Certificate Status {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }
        logger.debug("Updated Certificate Status {}", certificateAuthorityData);
    }

    /**
     * Deletes {@link CertificateAuthorityData} in the database.
     *
     * @param certificateAuthorityData
     *            object to be deleted in database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void deleteCA(final CertificateAuthorityData certificateAuthorityData) throws CoreEntityServiceException {

        try {
            persistenceManager.deleteEntity(certificateAuthorityData);

        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in updating Entity {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (final PersistenceException exception) {
            logger.error("Error in updating {}. {}", certificateAuthorityData.getName(), exception.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.OCCURED_IN_UPDATING + certificateAuthorityData.getName(), exception);
        }
        logger.debug("Deleted CAEntity {}", certificateAuthorityData.getName());
    }

    /**
     * Gets {@link CertificateAuthorityData} Entity in the database with id or name or both criteria.
     *
     * @param certificateAuthority
     *            object to be mapped with JPA entity and to be updated in database.
     * @return CertificateAuthorityData
     * @throws CoreEntityNotFoundException
     *             Thrown when any internal error occurs in system.
     * @throws CoreEntityServiceException
     */
    public CertificateAuthorityData getCAData(final CertificateAuthority certificateAuthority) throws CoreEntityNotFoundException, CoreEntityServiceException {

        final Map<String, Object> parameters = new HashMap<String, Object>();
        List<CertificateAuthorityData> caDataList = null;

        final Long entityId = certificateAuthority.getId();
        final String cAEntityName = certificateAuthority.getName();

        if (entityId == 0 && ValidationUtils.isNullOrEmpty(cAEntityName)) {
            logger.error(EntityManagementErrorCodes.ID_OR_NAME_SHOULD_PRESENT);
            throw new IllegalArgumentException(EntityManagementErrorCodes.ID_OR_NAME_SHOULD_PRESENT);
        }
        if (entityId != 0 && !ValidationUtils.isNullOrEmpty(cAEntityName)) {
            parameters.put("id", entityId);
            parameters.put("name", cAEntityName);
        } else if (entityId != 0) {
            parameters.put("id", entityId);
        } else {
            parameters.put("name", cAEntityName);
        }

        try {
            caDataList = persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters);
        } catch (final PersistenceException exception) {
            logger.error("Error in retreiving {} ", exception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, exception);
        }
        if (ValidationUtils.isNullOrEmpty(caDataList)) {
            logger.error(EntityManagementErrorCodes.CA_ENTITY_NOT_FOUND);
            throw new CoreEntityNotFoundException(EntityManagementErrorCodes.CA_ENTITY_NOT_FOUND);
        } else {
            return caDataList.get(0);
        }
    }

    /**
     * Gets Sub CA list with entityName in the DataBase.
     *
     * @param entityName
     * @return list of {@link CertificateAuthorityData}
     */
    public List<CertificateAuthorityData> getSubCAsUnderCA(final String entityName) {

        final Query query = persistenceManager.getEntityManager().createQuery(
                "select cd from CertificateAuthorityData cd where cd.issuerCA.id in (select ca.id from CertificateAuthorityData ca where ca.name=:name ))");
        query.setParameter("name", entityName);
        return query.getResultList();
    }

    /**
     * Checks weather Active Entities {@link EntityData} existed under CA Entity{@link CertificateAuthorityData}
     *
     * @param entityName
     * @throws CoreEntityInUseException
     *             in case of Entity is has Active Certificates
     */
    public void checkEntityUnderCA(final String entityName) throws CoreEntityInUseException {

        final long entityCount = getEntityCount(entityName);

        if (entityCount > 0) {
            logger.error(EntityManagementErrorCodes.ENTITY_IS_ACTIVE_UNDER_CA);
            throw new CoreEntityInUseException(EntityManagementErrorCodes.ENTITY_IS_ACTIVE_UNDER_CA);
        }

    }

    private long getEntityCount(final String entityName) {

        long rowCount = 0;
        final Query query = persistenceManager.getEntityManager().createQuery(
                "select count(*) from EntityInfoData e where e.status=2 and e.issuerCA.id in (select ed.id from CertificateAuthorityData ed where name=:name)");
        query.setParameter("name", entityName);

        if (query.getResultList() != null) {
            rowCount = (Long) query.getSingleResult();
        }

        return rowCount;
    }

    /**
     * This method is used to get the list of {@link CertificateAuthority} by the specified CAStatus.
     *
     * @param caStatuses
     * @return List<CertificateAuthority>
     */
    public List<CertificateAuthority> getAllCAsByStatus(final CAStatus... caStatuses) {
        final List<CertificateAuthority> certificateAuthorityList = new ArrayList<>();
        List<CertificateAuthorityData> caDataList = new ArrayList<>();
        final Map<String, Object> parameters = new HashMap<>();
        for (int i = 0; i < caStatuses.length; i++) {
            parameters.put("status", caStatuses[i]);
            try {
                caDataList = persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters);
            } catch (final PersistenceException e) {
                logger.debug("Unable to fetch Certificate authority ", e);
                logger.error("Unable to fetch Certificate authority {}", e.getMessage());
            }
        }
        for (final CertificateAuthorityData certificateAuthorityData : caDataList) {
            try {
                certificateAuthorityList.add(cAEntityMapper.toAPIModel(certificateAuthorityData));
            } catch (InvalidCRLGenerationInfoException | CRLServiceException | InvalidCertificateException e) {
                logger.error("Unable to fetch Certificate authority {}, {}", certificateAuthorityData.getName(), e.getMessage());
                logger.debug("Unable to fetch Certificate authority:", e);
            }
        }
        return certificateAuthorityList;
    }

    /**
     * Check complete SubCAs hierarchy under SubCA
     *
     * @param subCAList
     *
     * @throws CoreEntityInUseException
     *             thrown when the entity has Active certificates
     * @throws CoreEntityServiceException
     *             in case of db errors for entity operations
     */
    public void checkSubCAsUnderCA(final List<CertificateAuthorityData> subCAList) throws CoreEntityInUseException, CoreEntityServiceException {

        for (final CertificateAuthorityData caData : subCAList) {

            if (caData.getStatus() == CAStatus.ACTIVE) {
                logger.error(EntityManagementErrorCodes.CAENTITY_IS_ACTIVE_UNDER_CA);
                throw new CoreEntityInUseException(EntityManagementErrorCodes.CAENTITY_IS_ACTIVE_UNDER_CA);
            } else {
                listSubCAsUnderCA(caData);
            }
        }

    }

    /**
     * Method used to persist CertificateAuthorityData
     *
     * @param certificateAuthorityData
     *            object to be persisted in database.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case JPA entity already exists in the database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void persistCertificateAuthorityData(final CertificateAuthorityData certificateAuthorityData) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        try {
            persistenceManager.createEntity(certificateAuthorityData);

        } catch (final EntityExistsException entityExistsException) {
            logger.error("Entity Already Exists {}", entityExistsException.getMessage());
            throw new CoreEntityAlreadyExistsException(EntityManagementErrorCodes.ENTITY_ALREADY_EXISTS, entityExistsException);
        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Inactive Error in creating entity {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }
        logger.debug("Created {}", certificateAuthorityData);
    }

    private void listSubCAsUnderCA(final CertificateAuthorityData certificateAuthorityData) throws CoreEntityInUseException, CoreEntityServiceException {
        final String caEntityName = certificateAuthorityData.getName();
        final List<CertificateAuthorityData> subCAList = getSubCAsUnderCA(caEntityName);

        if (certificateAuthorityData.isRootCA()) {
            if (subCAList.size() == 1) {
                deleteCAEntity(certificateAuthorityData);
            } else {
                deleteRootCAfromList(subCAList);
                checkSubCAsUnderCA(subCAList);
            }
        } else if (ValidationUtils.isNullOrEmpty(subCAList)) {
            checkEntityUnderCA(caEntityName);
        } else {
            checkSubCAsUnderCA(subCAList);
        }

    }

    private void deleteRootCAfromList(final List<CertificateAuthorityData> caEntityList) {

        final Iterator<CertificateAuthorityData> iterator = caEntityList.iterator();
        while (iterator.hasNext()) {
            final CertificateAuthorityData certificateAuthorityData = iterator.next();
            if (certificateAuthorityData.isRootCA()) {
                iterator.remove();
                break;
            }

        }

    }

    private void deleteCAEntity(final CertificateAuthorityData caData) throws CoreEntityServiceException {
        try {
            persistenceManager.deleteEntity(caData);
        } catch (final PersistenceException e) {
            logger.error(ErrorMessages.INTERNAL_ERROR + " for deleting CAEntity");
            throw new CoreEntityServiceException(ErrorMessages.INTERNAL_ERROR + " for deleting CAEntity", e);
        }

    }

    /**
     * This method will update Entity status to INACTIVE for all the CAEntities who does not have active or inactive certificates.
     *
     * @throws CoreEntityServiceException
     */
    public void updateCAEntityStatusToInactive() throws CoreEntityServiceException {
        int updatedEntityCount = 0;
        final Query query = persistenceManager.getEntityManager().createNativeQuery(updateCAEntityStatusToInactiveNativeQuery);
        try {
            updatedEntityCount = query.executeUpdate();

        } catch (PersistenceException | IllegalStateException e) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CAEntity status");
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CAEntity status", e);
        }
        logger.info("Updated CAEntity status for {} entities in pki-core", updatedEntityCount);

    }

    /**
     * This method will update CA Entity status to the given status.
     *
     * @param certificateAuthorityData
     * @param status
     *
     * @throws CoreEntityServiceException
     */
    public void updateCAStatus(final CertificateAuthorityData certificateAuthorityData, final CAStatus status) throws CoreEntityServiceException {
        try {
            certificateAuthorityData.setStatus(status);
            persistenceManager.updateEntity(certificateAuthorityData);
        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in updating Entity {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }
    }
}
