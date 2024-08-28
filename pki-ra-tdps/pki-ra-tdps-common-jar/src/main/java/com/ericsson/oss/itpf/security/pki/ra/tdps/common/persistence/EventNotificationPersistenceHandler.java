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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence;

import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.errormessage.ErrorMessage;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.*;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;

/**
 * This class is used to handle the publish,unpublish certificates and persist entities using pkiratdps db
 * 
 * @author xchowja
 *
 */
public class EventNotificationPersistenceHandler {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    @Inject
    TDPSCertificateStatusMapper tdpsCertificateStatusMapper;

    @Inject
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    @Inject
    TDPSEntityDataMapper tDPSEntityDataMapper;

    /**
     * This method persists Entity into DB In case of any exceptions transaction is rolled back.
     * 
     * @param entitiesList
     *            List of entities to be persisted
     * @throws TrustDistributionServiceException
     *             is thrown in the case where exception occurs due to db operations
     */
    public void persistTdpsEntities(final List<TDPSEntityData> entitiesList) throws TrustDistributionServiceException {

        for (final TDPSEntityData eachEntity : entitiesList) {
            TDPSEntityData tDPSEntityData = null;
            try {
                tDPSEntityData = (TDPSEntityData) persistenceManager.getEntityManager().createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType")
                        .setParameter(Constants.ENTITY_NAME_PARAM, eachEntity.getEntityName()).setParameter(Constants.ENTITY_TYPE_PARAM, eachEntity.getEntityType())
                        .setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, eachEntity.getSerialNo()).setParameter(Constants.CERTIFICATE_STATUS_PARAM, eachEntity.getTdpsCertificateStatus())
                        .setParameter(Constants.ISSUER_NAME_PARAM, eachEntity.getIssuerName()).getSingleResult();
            } catch (final PersistenceException persistenceException) {
                logger.debug("Record not found for {} {} ", Constants.ENTITY_NAME_PARAM, eachEntity.getEntityName());
                logger.warn("Record not found due to ", persistenceException);
            }
            try {
                if (tDPSEntityData == null) {
                    persistenceManager.getEntityManager().persist(eachEntity);
                } else {
                    tDPSEntityData.setCertificate(eachEntity.getCertificate());
                    persistenceManager.getEntityManager().merge(tDPSEntityData);
                }
            } catch (final Exception exception) {
                logger.error("Error occured during DB operation {}", exception.getMessage());
                logger.warn("Persistence exception  while updating the Database, hence performing rollback on the previous operation.");
                throw new TrustDistributionServiceException(exception);
            }
        }

    }

    /**
     * This method persists Entity into DB In case of any exceptions transaction is rolled back.
     *
     * @param certificateInfo
     *            it contains the certificateInfo to publish the certificates to db
     * @throws TrustDistributionServiceException
     *             is thrown in the case where exception occurs due to db operations
     */
    public void publishTDPSCertificates(final TDPSCertificateInfo certificateInfo) throws TrustDistributionServiceException {

        try {

            final List<TDPSEntityData> tdpsEntityDataList = fetchTDPSEntityDataBasedOnNameAndType(certificateInfo);

            if (tdpsEntityDataList.isEmpty()) {
                final TDPSEntityData entity = tDPSEntityDataMapper.fromModel(certificateInfo);
                persistenceManager.getEntityManager().persist(entity);
            } else {
                final TDPSEntityData tDPSEntityData = tdpsEntityDataList.get(0);
                final byte[] encodedCertificate = certificateInfo.getEncodedCertificate();
                tDPSEntityData.setCertificate(encodedCertificate);
                tDPSEntityData.setSerialNo(certificateInfo.getSerialNumber());
                persistenceManager.getEntityManager().merge(tDPSEntityData);
            }

        } catch (final PersistenceException persistenceException) {
            logger.error("Unable to persist or merge the Record into db{}", persistenceException.getMessage());
            throw new TrustDistributionServiceException("Error occured during DB operations", persistenceException);
        }
    }

    /**
     * This method deletes particular entity from database. In case entity is detached, it is merged and then removed otherwise removed directly.
     *
     * @param certificateInfo
     *            it contains the certificateInfo to unpublish the certificates from db
     * @throws CertificateNotFoundException
     *             is thrown when certificate is not found in the database.
     * @throws TrustDistributionServiceException
     *             is thrown in the case where exception occurs due to db operations or in the case where it could not fetch entity
     */
    public void unPublishTDPSCertificates(final TDPSCertificateInfo certificateInfo) throws CertificateNotFoundException, TrustDistributionServiceException {
        try {

            final List<TDPSEntityData> tdpsEntityDataList = fetchTDPSEntityDataBasedOnNameAndType(certificateInfo);

            if (tdpsEntityDataList.isEmpty()) {
                throw new CertificateNotFoundException(ErrorMessage.ERR_CERTIFICATE_NOT_FOUND_IN_DB);
            }
            final TDPSEntityData tdpsEntity = tdpsEntityDataList.get(0);
            persistenceManager.getEntityManager().remove(persistenceManager.getEntityManager().contains(tdpsEntity) ? tdpsEntity : persistenceManager.getEntityManager().merge(tdpsEntity));

        } catch (final PersistenceException persistenceException) {
            logger.error("Unable to delete the Record from db{}", persistenceException.getMessage());
            throw new TrustDistributionServiceException("Error occured during DB operations", persistenceException);
        }
    }

    private List<TDPSEntityData> fetchTDPSEntityDataBasedOnNameAndType(final TDPSCertificateInfo certificateInfo) throws TrustDistributionServiceException {
        List<TDPSEntityData> tdpsEntityDataList = null;

        try {
            final String entityName = certificateInfo.getEntityName();
            final TDPSEntity entityType = tdpsEntityTypeMapper.fromModel(certificateInfo.getTdpsEntityType());
            final String serialNo = certificateInfo.getSerialNumber();
            final String issuerName = certificateInfo.getIssuerName();

            tdpsEntityDataList = persistenceManager.getEntityManager().createNamedQuery("TDPSEntityData.findByEntityNameAndType").setParameter("entityName", entityName)
                    .setParameter("entityType", entityType).setParameter("serialNo", serialNo).setParameter("issuerName", issuerName).getResultList();
        } catch (final PersistenceException persistenceException) {
            logger.error("Unable to get the Record from DB {}", persistenceException.getMessage());
            throw new TrustDistributionServiceException("Error occured during DB operations", persistenceException);
        }

        return tdpsEntityDataList;

    }
}
