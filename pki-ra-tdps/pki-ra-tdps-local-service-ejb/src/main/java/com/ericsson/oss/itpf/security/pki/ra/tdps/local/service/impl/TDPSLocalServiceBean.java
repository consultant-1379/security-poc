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
package com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.impl;

import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.EventNotificationPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;
import com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.api.TDPSLocalService;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;

/**
 * This Class is used to publish or unpublish certificates to TDPS db using TDPSCertificateInfo object
 * 
 * @author xchowja
 *
 */
@Stateless
public class TDPSLocalServiceBean implements TDPSLocalService {
    @Inject
    private EventNotificationPersistenceHandler eventNotificationPersistenceHandler;

    @Override
    public void publishTDPSCertificates(final TDPSCertificateInfo certificateInfo) throws TrustDistributionServiceException {
        eventNotificationPersistenceHandler.publishTDPSCertificates(certificateInfo);
    }

    @Override
    public void unPublishTDPSCertificates(final TDPSCertificateInfo certificateInfo) throws CertificateNotFoundException, TrustDistributionServiceException {
        eventNotificationPersistenceHandler.unPublishTDPSCertificates(certificateInfo);
    }

    @Override
    public void persistTdpsEntities(final List<TDPSEntityData> entitiesList) throws TrustDistributionServiceException {
        eventNotificationPersistenceHandler.persistTdpsEntities(entitiesList);
    }

}
