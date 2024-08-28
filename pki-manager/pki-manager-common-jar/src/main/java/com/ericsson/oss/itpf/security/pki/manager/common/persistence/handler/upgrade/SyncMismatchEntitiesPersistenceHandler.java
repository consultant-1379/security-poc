/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.upgrade;

import java.math.BigInteger;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.SubjectIdentificationData;

/**
 * This class is used to remove the inconsistencies between hash of subject_dn column of entity table and subject_dn_hash of subject_identification_details table. after the cluster upgrade.
 * 
 * @author tcschdy
 *
 */
public class SyncMismatchEntitiesPersistenceHandler {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    EntityPersistenceHandler<Entity> entityPersistenceHandler;

    @Inject
    Logger logger;

    private static final String getMissingEntities = "select id from entity where id not in (select entity_id from subject_identification_details)";
    private static final String getSurplusEntities = "select id from subject_identification_details where entity_id not in (select id from entity)";
    private static final String getMismatchEntities = "select entity_id from subject_identification_details sd, entity ee where encode(sd.subject_dn_hash, 'hex') != encode(digest(lower(ee.subject_dn), 'sha256'), 'hex') and  sd.entity_id=ee.id;";

    private static final String deleteError = "Error occured during deleting the entities information that is present in subect_identification_details table and not present in entity table ";
    private static final String persistError = "Error occured during persisting the entities information that is present in entity table and not present in subect_identification_details table ";
    private static final String updateError = "Error occured during updating the entities that are modified in entity table and are not updated in subect_identification_details table";

    /**
     * This method is used to remove the inconsistencies between hash of subject_dn column of entity table and subject_dn_hash of subject_identification_details table. after cluster upgrade.
     * 
     * @param entityPersistenceHandler
     */
    public void syncMismatchEntities() {
        persistMissingEntities();
        deleteSurplusEntities();
        updateMismatchEntities();

    }

    private void persistMissingEntities() {
        try {
            final List<BigInteger> entityIds = persistenceManager.findIdsByNativeQuery(getMissingEntities);

            for (BigInteger entityId : entityIds) {
                final EntityData targetEntityData = (EntityData) entityPersistenceHandler.getEntityById(entityId.longValue(), EntityData.class);
                targetEntityData.getEntityInfoData().setSubjectDN(SubjectUtils.orderSubjectDN(targetEntityData.getEntityInfoData().getSubjectDN()));
                persistenceManager.updateEntity(targetEntityData);
                entityPersistenceHandler.persistSubjectIdentificationData(targetEntityData);
            }
        } catch (final EntityAlreadyExistsException entityAlreadyExistsException) {
            logger.error(persistError, entityAlreadyExistsException.getMessage());

        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.error(persistError, entityNotFoundException.getMessage());

        } catch (final EntityServiceException entityServiceException) {
            logger.error(persistError, entityServiceException.getMessage());

        } catch (final PersistenceException persistenceException) {
            logger.error(persistError, persistenceException.getMessage());

        }
    }

    private void deleteSurplusEntities() {
        try {
            final List<BigInteger> entityIds = persistenceManager.findIdsByNativeQuery(getSurplusEntities);

            for (BigInteger entityId : entityIds) {
                final SubjectIdentificationData targetEntityData = (SubjectIdentificationData) entityPersistenceHandler.getEntityById(entityId.longValue(), SubjectIdentificationData.class);
                persistenceManager.deleteEntity(targetEntityData);
            }
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.error(deleteError, entityNotFoundException.getMessage());

        } catch (final EntityServiceException entityServiceException) {
            logger.error(deleteError, entityServiceException.getMessage());

        } catch (final PersistenceException persistenceException) {
            logger.error(deleteError, persistenceException.getMessage());

        }

    }

    private void updateMismatchEntities() {
        try {
            final List<BigInteger> entityIds = persistenceManager.findIdsByNativeQuery(getMismatchEntities);

            for (BigInteger entityId : entityIds) {
                final EntityData targetEntityData = (EntityData) entityPersistenceHandler.getEntityById(entityId.longValue(), EntityData.class);
                targetEntityData.getEntityInfoData().setSubjectDN(SubjectUtils.orderSubjectDN(targetEntityData.getEntityInfoData().getSubjectDN()));
                persistenceManager.updateEntity(targetEntityData);
                entityPersistenceHandler.updateSubjectIdentificationData(targetEntityData);
            }
        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.error(updateError, algorithmNotFoundException.getMessage());

        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.error(updateError, entityNotFoundException.getMessage());

        } catch (final EntityServiceException entityServiceException) {
            logger.error(updateError, entityServiceException.getMessage());

        } catch (final PersistenceException persistenceException) {
            logger.error(updateError, persistenceException.getMessage());

        }

    }

}
