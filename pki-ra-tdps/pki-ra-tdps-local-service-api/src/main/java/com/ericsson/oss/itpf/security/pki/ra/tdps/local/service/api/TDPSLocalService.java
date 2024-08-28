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
package com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.api;

import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;

/**
 * This interface is used to publish or unpublish certificates to TDPS db using TDPSCertificateInfo object
 * 
 * @author xchowja
 *
 */
@EService
@Local
public interface TDPSLocalService {

    /**
     * This method is used to publish certificates to TDPS db using TDPSCertificateInfo object
     * 
     * @param certificateInfo
     *            it contains the certificateInfo to publish the certificates to db
     * @throws TrustDistributionServiceException
     */
    void publishTDPSCertificates(final TDPSCertificateInfo certificateInfo) throws TrustDistributionServiceException;

    /**
     * This method is used to unpublish certificates to TDPS db using TDPSCertificateInfo object
     * 
     * @param certificateInfo
     *            it contains the certificateInfo to unpublish the certificates from db
     * @throws CertificateNotFoundException
     *             is thrown when certificate is not found in the database.
     * @throws TrustDistributionServiceException
     *             is thrown in the case where exception occurs due to db operations or in the case where it could not fetch entity
     */
    void unPublishTDPSCertificates(final TDPSCertificateInfo certificateInfo) throws CertificateNotFoundException, TrustDistributionServiceException;

    /**
     * This method is used to persist the TDPSEntityData list into the TDPS db
     * 
     * @param entitiesList
     *            List of entities to be persisted
     * @throws TrustDistributionServiceException
     *             is thrown in the case where exception occurs due to db operations or in the case where it could not fetch entity
     */
    void persistTdpsEntities(final List<TDPSEntityData> entitiesList) throws TrustDistributionServiceException;
}
