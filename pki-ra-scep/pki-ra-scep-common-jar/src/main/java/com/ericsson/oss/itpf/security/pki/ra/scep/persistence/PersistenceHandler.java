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
package com.ericsson.oss.itpf.security.pki.ra.scep.persistence;

import java.sql.Timestamp;
import java.util.*;
import java.util.Map.Entry;

import javax.inject.Inject;
import javax.persistence.*;
import javax.persistence.criteria.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;

/**
 * 
 * This class deals with all CRUD operation of persistence unit: PERSIST_UNIT = "JPAD".
 * 
 * 
 * @author xchowja
 *
 */
public class PersistenceHandler {

    @PersistenceContext(unitName = PersistenceUnit.PERSIST_UNIT)
    public EntityManager entityManager;

    @Inject
    Logger logger;

    @Inject
    private Pkcs7ScepRequestEntity pkcs7ScepRequestEntity;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is used to update the SCEP response status(failure ,success, pending) in pkirascep db based on ScepResponse object
     * 
     * @param scepResponse
     */
    public void updateSCEPResponseStatus(final ScepResponse scepResponse) {
        pkcs7ScepRequestEntity = buildPkcs7ScepRequestEntity(scepResponse);
        updatePkcs7ScepRequestEntity(pkcs7ScepRequestEntity);
    }

    /**
     * This method updates the record in database.
     * 
     * @param pkcs7ScepRequestEntity
     *            is the entity to be updated in database with the new values.
     * 
     * @param entityManager
     *            is the instance on entity manager for a given persistent context.
     * 
     */
    @Profiled
    public void updatePkcs7ScepRequestEntity(final Pkcs7ScepRequestEntity pkcs7ScepRequestEntity) {
        logger.debug("updatePkcs7ScepRequestEntity method in ResponseProcessor class  ");
        entityManager.merge(pkcs7ScepRequestEntity);
        entityManager.flush();
        systemRecorder.recordEvent("PKI_RA_SCEP.RESPONSE_PERSISTED", EventLevel.COARSE, "Response Processor", "PKIRASCEPService",
                "SCEP response persisted for a given PKCSReq message with the Transaction Id :" + pkcs7ScepRequestEntity.getTransactionId());
    }

    private Pkcs7ScepRequestEntity buildPkcs7ScepRequestEntity(final ScepResponse scepResponse) {
        logger.debug("buildPKCS7ScepRequestEntity method in ResponseProcessor class  ");
        pkcs7ScepRequestEntity = entityManager.find(Pkcs7ScepRequestEntity.class, scepResponse.getTransactionId());

        pkcs7ScepRequestEntity.setFailInfo(scepResponse.getFailureInfo());
        pkcs7ScepRequestEntity.setCertificate(scepResponse.getCertificate());
        pkcs7ScepRequestEntity.setStatus(scepResponse.getStatus());
        pkcs7ScepRequestEntity.setTransactionid(scepResponse.getTransactionId());

        return pkcs7ScepRequestEntity;
    }

    /**
     * persistPkcs7ScepRequestEntity checks the for the record with transaction id, It persists the Pkcs7ScepRequestEntity into Database if that record is not present in the database.
     *
     * @param pkcs7ScepRequestEntity
     *            is the entity record to be persisted to Database.
     */
    @Profiled
    public void persistPkcs7ScepRequestEntity(final Pkcs7ScepRequestEntity pkcs7ScepRequestEntity) throws PersistenceException {
        logger.debug("persistPkcs7ScepRequestEntity method in PersistanceHandler class ");
        if (getPkcs7ScepRequestEntity(pkcs7ScepRequestEntity.getTransactionId()) == null) {
            entityManager.persist(pkcs7ScepRequestEntity);
        }
        logger.debug("End of persistPkcs7ScepRequestEntity method in PersistanceHandler class  ");
    }

    /**
     * It fetches the Pkcs7ScepRequestEntity Record based on transactionId from Database.
     *
     * @param transactionId
     *            is the unique serial number for the transaction.
     * @return pkcs7ScepRequestEntity is the entity object,which contains the information to prepare the response.
     *
     */
    @Profiled
    public Pkcs7ScepRequestEntity getPkcs7ScepRequestEntity(final String transactionId) throws PersistenceException {
        logger.debug("getPkcs7ScepRequestEntity method in PersistanceHandler class  ");
        return entityManager.find(Pkcs7ScepRequestEntity.class, transactionId);
    }

    /**
     * Find entities by attributes
     *
     * @param entityClass
     *            Class name of the entity to be retrieved.
     * @param attributes
     *            Attributes map containing entity property names as key and the corresponding attribute data as values.
     * @return list of entities which matches the given search criteria.
     */
    @Profiled
    public <T> List<T> searchEntitiesByAttributes(final Class<T> entityClass, final Map<String, Object> attributesMap) {
        logger.debug("searchEntitiesByAttributes method in PersistanceHandler class  ");
        final CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        final CriteriaQuery<T> criteriaQuery = criteriaBuilder.createQuery(entityClass);
        final Root<T> entity = criteriaQuery.from(entityClass);

        final Set<String> attributesKeySet = attributesMap.keySet();
        final List<Predicate> predicates = new ArrayList<>();
        for (final String attribute : attributesKeySet) {
            final Object object = attributesMap.get(attribute);
            if (entity.get(attribute) != null && object != null) {
                if (object instanceof String || object instanceof Boolean || object instanceof Integer) {
                    predicates.add(criteriaBuilder.equal(entity.get(attribute), attributesMap.get(attribute)));
                } else if (object instanceof List) {
                    predicates.add(entity.get(attribute).in(object));
                }
            }
        }
        criteriaQuery.where(predicates.toArray(new Predicate[] {}));
        final TypedQuery<T> query = entityManager.createQuery(criteriaQuery);
        final List<T> results = query.getResultList();
        logger.debug("End of searchEntitiesByAttributes method in PersistanceHandler class ");
        return results;
    }

    /**
     * This method will hard delete the records from SCEP data base which are older than the given recordPurgePeriod
     *
     * @param recordPurgePeriod
     *            An integer value which indicates the number of days the records in SCEP data base to be purged
     */
    public void deleteOldRecordsFromScepDb(final int recordPurgePeriod) {
        logger.debug("Entering the method deleteRecordsFromScepDb of class PersistenceHandler");
        final long purgePeriod = convertDaysToTimeStamp(recordPurgePeriod);
        Timestamp intervalTime = null;
        try {
            logger.info("SCEP DB records clean up, which are older than {} has been started", recordPurgePeriod);
            intervalTime = new Timestamp(System.currentTimeMillis() - purgePeriod);
            final Query query = entityManager.createNamedQuery("Pkcs7ScepRequestEntity.deleteEntity").setParameter("intervalTime", intervalTime);
            query.executeUpdate();
            logger.info("SCEP DB records, which are older than {} has been cleaned up successfully", recordPurgePeriod);
        } catch (Exception exception) {
            logger.warn("DB clean up process couldn't be started for {} ", intervalTime);
            logger.error("Error occured while Database cleanup process {} ", exception.getMessage());
            systemRecorder.recordError("PKI_RA_SCEP.DB_CLEANUP_ERROR", ErrorSeverity.ERROR, "PKIRASCEPService", "PKIRASCEPServiceDBCleanup", "Error occured while Database cleanup process");
        }
        logger.debug("End of the method deleteRecordsFromScepDb of class PersistenceHandler");
    }

    private long convertDaysToTimeStamp(final int scepRequestRecordPurgePeriod) {
        return scepRequestRecordPurgePeriod * (24 * 60L * 60L * 1000L);
    }
}
