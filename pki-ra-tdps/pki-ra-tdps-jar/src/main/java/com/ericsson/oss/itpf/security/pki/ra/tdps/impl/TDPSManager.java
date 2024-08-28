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
package com.ericsson.oss.itpf.security.pki.ra.tdps.impl;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionResourceNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.DataLookupException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.PersistenceManager;

/**
 * This class deals with retrieving certificate based on entityType and name. It is just an abstraction for persistence manager.
 * 
 * @author tcsdemi
 *
 */

public class TDPSManager {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is used to fetch certificate from Database.
     * 
     * @param trustDistributionParameters
     *            All the input parameters which are sent in URL i.e entityType,entityName,certificateStatus,certificateSerialId,issuerName
     * 
     * 
     * @throws CertificateNotFoundException
     *             Thrown when certificate is not found in Database, reason could be certificate is not yet published.
     * 
     * @throws TrustDistributionServiceException
     *             Thrown when duplicate certificates are found in Database with a given combination of Entity Name and EntityType and also throws any persistence related exceptions occurs.
     */
    public byte[] getCertificate(final TrustDistributionParameters trustDistributionParameters) throws CertificateNotFoundException, TrustDistributionServiceException {
        final String trustDistributionParameter = trustDistributionParameters.toString();
        logger.debug("Querying for Certificate {}", trustDistributionParameter);
        byte[] trustCertBasedOnCAName = null;

        try {
            trustCertBasedOnCAName = persistenceManager.getCertificate(trustDistributionParameters.getEntityName(), trustDistributionParameters.getEntityType(),
                    trustDistributionParameters.getIssuerName(), trustDistributionParameters.getCertificateStatus(), trustDistributionParameters.getCertificateSerialId());
        } catch (CertificateNotFoundException certificateNotFoundException) {
            logger.debug("Exception StackTrace: ", certificateNotFoundException);
            systemRecorder.recordError("TDPS_SERVICE.TRUST_CERTIFICATE_NOT_FOUND", ErrorSeverity.ERROR, "Get Trusted Certificate", "Trusted Certificates of Entity which invoked TDPS", certificateNotFoundException.getMessage());
            throw new TrustDistributionResourceNotFoundException(certificateNotFoundException);
        } catch (DataLookupException dataLookupException) {
            logger.debug("Exception StackTrace: ", dataLookupException);
            systemRecorder.recordError("TDPS_SERVICE.DUPLICATE_RECORDS_FOUND", ErrorSeverity.ERROR, "Get Trusted Certificate", "Trusted Certificates of Entity which invoked TDPS", dataLookupException.getMessage());
            throw new TrustDistributionServiceException(dataLookupException);
        }

        return trustCertBasedOnCAName;
    }

}
