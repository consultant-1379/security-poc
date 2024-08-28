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
package com.ericsson.oss.itpf.security.pki.cdps.common;

import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CRLInfoMapper;

/**
 * EventNotificationPersistenceHandler class will Publish or UnPublish the CRL into CDPS
 * 
 * @author xjagcho
 * 
 */
public class EventNotificationPersistenceHandler {
    @Inject
    private CACertificateInfoMapper caCertificateInfoMapper;

    @Inject
    private CRLInfoMapper crlInfoMapper;


    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private PersistenceManager persistenceManager;

    @Inject
    private Logger logger;

    /**
     * This method process the Publish CRL request to publish CRL and persist in DB
     * 
     * @param crlInfolList
     *            it holds CACertificateInfo it contains caName and certificate serial number and encoded CRL
     * 
     * @throws CRLDistributionPointServiceException
     *             throws when persist entities to database table
     */
    public void publishCRL(final List<CRLInfo> crlInfolList) throws CRLDistributionPointServiceException {
        logger.debug("publishCRL method in EventNotificationPersistenceHandler class");

        final List<CDPSEntityData> cdpsEntityDatas = crlInfoMapper.fromModel(crlInfolList);
        publishCRLs(cdpsEntityDatas);

        logger.debug("End of publishCRL method in EventNotificationPersistenceHandler class");
    }

    /**
     * This method process the UnPublish CRL request using caCertificateInfos list object as argument
     * 
     * @param caCertificateInfos
     *            it holds caName and certificate serial number
     * @throws CRLDistributionPointServiceException
     *             throws when delete entities from database
     */
    public void unPublishCRL(final List<CACertificateInfo> caCertificateInfos) throws CRLDistributionPointServiceException {
        logger.debug("unPublishCRL method in EventNotificationPersistenceHandler class");

        final List<CDPSEntityData> cdpsEntityDatas = caCertificateInfoMapper.fromModel(caCertificateInfos);
        unPublishCRLs(cdpsEntityDatas);

        logger.debug("End of unPublishCRL method in EventNotificationPersistenceHandler class");
    }
    
    private void publishCRLs(final List<CDPSEntityData> cdpsEntityDatas) throws CRLDistributionPointServiceException {
        logger.debug("Persisting entity {}", cdpsEntityDatas);

        try {
            for (CDPSEntityData cdpsEntityData : cdpsEntityDatas) {
                
                final String caName = cdpsEntityData.getCaName();
                final String serialNumber = cdpsEntityData.getCertSerialNumber();

                final List<?> results = persistenceManager.getEntityManager().createNamedQuery("CDPSEntityData.findByCaNameAndSerialNumber").setParameter("caName", caName)
                        .setParameter("serialNumber", serialNumber).getResultList();

                if (results.isEmpty()) {
                    logger.debug("No entries found in the DB for {} and {}. So inserting CRL in the DB", caName, serialNumber);
                    persistenceManager.createEntity(cdpsEntityData);
                } else {
                    logger.debug("Entries found in the DB for {} and {}. So updating the CRL in the DB", caName, serialNumber);
                    final CDPSEntityData foundEntityData = (CDPSEntityData) results.get(0);
                    foundEntityData.setCrl(cdpsEntityData.getCrl());

                    persistenceManager.updateEntity(foundEntityData);
                }
            }
        } catch (PersistenceException persistenceException) {
            logger.error("Error occured during DB operation {}", persistenceException.getMessage());
            systemRecorder.recordError("PKI_CDPS.DB_OPEARTION_ERROR", ErrorSeverity.ERROR, "CDPSService", "CDPSService", "DB Error occured during publish crl");

            throw new CRLDistributionPointServiceException("Error occured during DB operations", persistenceException);
        }
    }
    
    private void unPublishCRLs(final List<CDPSEntityData> cdpsEntityDatas) throws CRLDistributionPointServiceException {
        logger.debug("Deleting Entity {}", cdpsEntityDatas);

        try {
            for (CDPSEntityData cdpsEntityData : cdpsEntityDatas) {
                final String caName = cdpsEntityData.getCaName();
                final String serialNumber = cdpsEntityData.getCertSerialNumber();

                final List<?> results = persistenceManager.getEntityManager().createNamedQuery("CDPSEntityData.findByCaNameAndSerialNumber").setParameter("caName", caName)
                        .setParameter("serialNumber", serialNumber).getResultList();

                if (!results.isEmpty()) {
                    final CDPSEntityData entityData = (CDPSEntityData) results.get(0);
                    persistenceManager.deleteEntity(entityData);
                } else {
                    logger.debug("It is already unpublished CRL for {}, {}", caName, serialNumber);
                }
            }
        } catch (PersistenceException persistenceException) {
            logger.error("Error occured during DB operation {}", persistenceException.getMessage());
            systemRecorder.recordError("PKI_CDPS.DB_OPEARTION_ERROR", ErrorSeverity.ERROR, "CDPSService", "CDPSService", "DB Error occured during unpublish crl");

            throw new CRLDistributionPointServiceException("Error occured during DB operations", persistenceException);
        }
    }
}