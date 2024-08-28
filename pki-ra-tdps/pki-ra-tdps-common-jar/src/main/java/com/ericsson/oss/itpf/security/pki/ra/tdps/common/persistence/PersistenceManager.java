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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence;

import java.util.List;

import javax.inject.Inject;
import javax.persistence.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.persistence.AbstractPersistenceManager;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.DataLookupException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;

/**
 * This is a persitenceManager class which is used to hold all DB related methods.
 * 
 * @author tcsdemi
 *
 */
public class PersistenceManager extends AbstractPersistenceManager {

    private static final String DB_RETRIVE_UNIT = "tdpsPersistenceUnit";

    @PersistenceContext(unitName = DB_RETRIVE_UNIT)
    public EntityManager entityManager;

    @Inject
    Logger logger;

    /**
     * Returns entity manager.
     * 
     * @return the entityManager
     */
    public EntityManager getEntityManager() {
        return entityManager;
    }

    private static final String STRING_FORMATTER = "for EntityName: " + "%s" + " of entity type: " + "%s" + " having " + "%s" + " certificate with serial Id as " + "%s" + " issued by CA " + "%s";

    /**
     * This method is used to fetch certificate from Database.
     * 
     * @param entityType
     *            Type of the entity i.e CA or Entity
     * 
     * @param entityName
     *            Common Name of the entity
     * 
     * @param serialNo
     *            Certificate serial number.
     * @return
     * @throws CertificateNotFoundException
     *             Thrown when certificate is not found in Database, reason could be certificate is not yet published.
     * 
     * @throws DataLookupException
     *             Thrown when duplicate certificates are found in Database with a given combination of Entity Name and EntityType and also throws any persistence related exceptions occurs.
     */
    public byte[] getCertificate(final String entityName, final String entityType, final String issuerName, final String certificateStatus, final String certificateSerialID)
            throws CertificateNotFoundException, DataLookupException {

        List<TDPSEntityData> tdpsEntities = null;
        byte[] certificateBytes = null;

        try {
            final Query query = entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType");
            tdpsEntities = (List<TDPSEntityData>) query.setParameter(Constants.ENTITY_NAME_PARAM, entityName).setParameter(Constants.ENTITY_TYPE_PARAM, TDPSEntity.valueOf(entityType.toUpperCase()))
                    .setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, certificateSerialID).setParameter(Constants.CERTIFICATE_STATUS_PARAM, TDPSCertificateStatus.valueOf(certificateStatus))
                    .setParameter(Constants.ISSUER_NAME_PARAM, issuerName).getResultList();
            certificateBytes = tdpsEntities.get(0).getCertificate();

        } catch (NoResultException noResultException) {
            logger.error("DB is empty or certificate is not found {} ", String.format(STRING_FORMATTER, entityName, entityType, certificateStatus, certificateSerialID, issuerName));
            throw new CertificateNotFoundException(noResultException);
        } catch (NonUniqueResultException nonUniqueResultException) {
            logger.error("There could be multiple records in DB {} ", String.format(STRING_FORMATTER, entityName, entityType, certificateStatus, certificateSerialID, issuerName));
            throw new DataLookupException(nonUniqueResultException);
        } catch (PersistenceException persistenceException) {
            logger.error("Internal DB error while fetching data {}", String.format(STRING_FORMATTER, entityName, entityType, certificateStatus, certificateSerialID, issuerName));
            throw new DataLookupException(persistenceException);
        }

        return certificateBytes;
    }

}
