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
package com.ericsson.oss.itpf.security.pki.ra.cmp.persistence;

import java.util.Date;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.CMPRequestType;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

/**
 *
 * This class deals with all CRUD operation of persistence unit: PERSIST_UNIT = "pkiradb".
 *
 *
 * @author tcsdemi
 *
 */
public class PersistenceHandler {

    @PersistenceContext(unitName = PersistenceUnit.PERSIST_UNIT)
    public EntityManager entityManager;

    @Inject
    Logger logger;

    @Inject
    ConfigurationParamsListener configurationParamsListener;

    /**
     * Fetch CMPMessageEntity based on transactionID from the dB, in case entity is null for that particular status then <code> null</code> status is returned. Calling function should handle this
     * <code> null</code> status.
     * 
     * @param transactionID
     * @return CMPMessageEntity
     */
    public MessageStatus fetchStatusByTransactionID(final String transactionID) {
        MessageStatus updatesStatus = null;
        CMPMessageEntity cMPMsgEntity = null;
        cMPMsgEntity = entityManager.find(CMPMessageEntity.class, transactionID);

        if (cMPMsgEntity != null) {
            updatesStatus = cMPMsgEntity.getStatus();
        }
        return updatesStatus;

    }

    /**
     * Fetch CMPMessageEntity based on transactionID from the dB, in case entity is null for that particular status then <code> null</code> status is returned. Calling function should handle this
     * <code> null</code> status.
     * 
     * @param transactionID
     * @return CMPMessageEntity
     */
    public CMPMessageEntity fetchEntityByTransactionID(final String transactionID) {
        CMPMessageEntity cMPMessageEntity = null;
        cMPMessageEntity = (CMPMessageEntity) entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId").setParameter("transactionID", transactionID).getSingleResult();
        return cMPMessageEntity;

    }

    /**
     * To fetch the sender name based on the trasactionID
     * 
     * @param transactionID
     * @return sender name
     */
    public String fetchSenderNameByTransactionID(final String transactionID) {
        String senderName = "";
        CMPMessageEntity cMPMessageEntity = null;
        try {
            cMPMessageEntity = (CMPMessageEntity) entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId").setParameter("transactionID", transactionID).getSingleResult();
            senderName = cMPMessageEntity.getSenderName();
        } catch (final NoResultException noResultException) {
            final String warning = "DB is empty or there is no message entity with transaction Id as " + transactionID;
            logger.warn(warning, noResultException);
        }
        return senderName;

    }

    /**
     * Fetch CMPMessageEntity based on transactionID and senderName from the db. The combination of transactionId and senderName should be unique. Fetching only singleresult, since there should be
     * only one row with the same combination.
     *
     * @param transactionID
     * @param senderName
     * @return CMPMessageEntity
     */
    @SuppressWarnings("unchecked")
    public CMPMessageEntity fetchEntityByTransactionIdAndEntityName(final String transactionID, final String senderName) {
        CMPMessageEntity cmpMessageEntity = null;
        List<CMPMessageEntity> cMPMessageEntity = null;
        try {
            cMPMessageEntity = (List<CMPMessageEntity>) entityManager.createNamedQuery("CMPMessageEntity.findBySenderNameAndTransactionId").setParameter("senderName", senderName)
                    .setParameter("transactionID", transactionID).getResultList();
            if (cMPMessageEntity == null || cMPMessageEntity.isEmpty()) {
                cMPMessageEntity = (List<CMPMessageEntity>) entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId").setParameter("transactionID", transactionID).getResultList();
            }
        } catch (final NoResultException noResultException) {
            final String warning = "DB is empty or there is no message entity with transaction Id as " + transactionID;
            logger.warn(warning, noResultException);
        }
        if (cMPMessageEntity != null && !(cMPMessageEntity.isEmpty())) {
            cmpMessageEntity = cMPMessageEntity.get(0);
        }
        return cmpMessageEntity;

    }

    /**
     * UpdateEntity in DB. CMPMessageENtity is formed and given as an input parameter. *
     * 
     * @param cmpMessageEntity
     */
    public void updateEntity(final CMPMessageEntity cmpMessageEntity) throws PersistenceException {
        entityManager.merge(cmpMessageEntity);
        entityManager.flush();
    }

    /**
     * This method is used to update the CMP transaction status in pkiracmp DB using required transactionID,senderName,signedResponsea and status
     * 
     * @param transactionID
     * @param senderName
     * @param signedResponse
     * @param status
     */
    public void updateCMPTransactionStatus(final String transactionID, final String senderName, final byte[] signedResponse, final MessageStatus status) throws PersistenceException {
        final CMPMessageEntity cMPMessageEntity = buildProtocolMessageEntity(transactionID, senderName, signedResponse, status);
        updateEntity(cMPMessageEntity);
    }

    /**
     * This method is used to update the CMP transaction status in pkiracmp DB using required transactionID,senderName,signedResponse,status and senderNonce
     * 
     * @param transactionID
     * @param senderName
     * @param signedResponse
     * @param status
     * @param senderNonce
     */
    public void updateCMPTransactionStatus(final String transactionID, final String senderName, final byte[] signedResponse, final MessageStatus status, final String senderNonce) {
        final CMPMessageEntity cMPMessageEntity = buildProtocolMessageEntity(transactionID, senderName, signedResponse, status);
        cMPMessageEntity.setSenderNonce(senderNonce);
        updateEntity(cMPMessageEntity);
    }

    private CMPMessageEntity buildProtocolMessageEntity(final String transactionID, final String senderName, final byte[] pKIMessage, final MessageStatus status) {
        final CMPMessageEntity cMPMsgEntity = fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        cMPMsgEntity.setResponseMessage(pKIMessage);
        cMPMsgEntity.setStatus(status);
        cMPMsgEntity.setModifyTime(DateUtility.getUTCTime());
        return cMPMsgEntity;
    }

    /**
     * Persist entity in DB
     * 
     * @param pKIRequestMessage
     * @param transactionID
     */
    public void persist(final RequestMessage pKIRequestMessage, final String transactionID) {
        logger.info("Saving :{} into DB", pKIRequestMessage.getRequestMessage());
        final CMPMessageEntity messageEntity = new CMPMessageEntity();
        messageEntity.setTransactionID(transactionID);
        messageEntity.setInitialMessage(pKIRequestMessage.toByteArray());
        messageEntity.setSenderName(pKIRequestMessage.getSenderName());
        messageEntity.setCreateTime(DateUtility.getUTCTime());
        messageEntity.setModifyTime(DateUtility.getUTCTime());
        messageEntity.setStatus(MessageStatus.NEW);
        messageEntity.setRequestType(pKIRequestMessage.getRequestMessage());
        entityManager.persist(messageEntity);
        logger.info("Saved :{} into DB", pKIRequestMessage.getRequestMessage());

    }

    /**
     * Fetch CMPMessageEntity based on messageStatus.
     *
     * @param messageStatus
     *            on which entity records has to be fetched.
     * @return list of messageEntities
     */
    public List<CMPMessageEntity> fetchMessageEntitiesBasedOnStatus(final MessageStatus messageStatus) {
        return entityManager.createNamedQuery("CMPMessageEntity.findByStatus").setParameter("status", messageStatus).getResultList();
    }

    /**
     * This method retrieves records which based on status and requestType for eg: fetch records with status as NEW and requestType as INITIALIZATION REQUEST.<br>
     * eg: RequestType is set as CMPRequestType.INITIALIZATION_REQUEST.toString()
     *
     * @param messageStatus
     * @param requestType
     * @return
     */
    public List<CMPMessageEntity> fetchMessageEntitiesBasedOnStatusAndReqType(final MessageStatus messageStatus, final CMPRequestType requestType) {
        return entityManager.createNamedQuery("CMPMessageEntity.findByStatusAndRequestType").setParameter("status", messageStatus).setParameter("requestType", requestType.toString()).getResultList();
    }

    /**
     * This method is used to update entity status.
     *
     * @param cMPMessageEntity
     *            for which status has to be updated.
     * @param statusToUpdate
     *            status to update.
     */
    public void updateEntityStatus(final CMPMessageEntity cMPMessageEntity, final MessageStatus statusToUpdate) {
        cMPMessageEntity.setStatus(statusToUpdate);
    }

    /**
     * This method is used to delete records from CMP database whose created date is older than the given date
     *
     * @param dateToCompare
     *            Date value older than which the record in CMP database has to be deleted
     */
    public void deleteRecordsByCreatedDate(final Date dateToCompare) {

         entityManager.createNamedQuery("CMPMessageEntity.deleteByCreatedDate").setParameter("dateToCompare", dateToCompare).executeUpdate();

    }

    /**
     * This method is used to update status of the records with WAIT_FOR_ACK to TO_BE_REVOKED_NEW whose created date is older than the given date
     *
     * @param dateToCompare
     *            Date value older than which the record in CMP database has to be updated
     */
    public void updateRecordsStatusByCreatedDate(final Date dateToCompare) {

        entityManager.createNamedQuery("CMPMessageEntity.updateStatusByCreatedDate").setParameter("revokeStatus", MessageStatus.TO_BE_REVOKED_NEW)
                .setParameter("waitStatus", MessageStatus.WAIT_FOR_ACK).setParameter("dateToCompare", dateToCompare).executeUpdate();

    }

    /**
     * This method is used to fetch the cmp message entities with To BE REVOKED status.
     * 
     * @param maxLimit
     *            max limit to fetch the entities.
     * @return
     */
    public List<CMPMessageEntity> fetchToBeRevokedMessages(final int maxLimit) {
        return entityManager.createNamedQuery("CMPMessageEntity.findToBeRevokedEntitiesByOldModifiedDate")
                .setParameter("newRevokeStatus", MessageStatus.TO_BE_REVOKED_NEW).setParameter("oldRevokeStatus", MessageStatus.TO_BE_REVOKED_OLD)
                .setMaxResults(maxLimit).getResultList();
    }

}
