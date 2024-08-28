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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.TrustDistributionLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class is used as a local service for retrieving trust certificates and updating certificate status once acknowledgement is sent from TDPS.
 * 
 * @author tcsdemi
 *
 */
@Stateless
public class TrustDistributionLocalServiceBean implements TrustDistributionLocalService {

    @Inject
    TDPSPersistenceHandler tDPSPersistenceHandler;

    @Inject
    Logger logger;

    @Override
    public Map<String, List<Certificate>> getPublishedCertificates(final EntityType entityType) throws CertificateException, IOException, PersistenceException {
        Map<String, List<Certificate>> activeCertificatesMap = null;

        switch (entityType) {
        case CA_ENTITY: {
            activeCertificatesMap = tDPSPersistenceHandler.getPublishableCACertificates();
            break;
        }
        case ENTITY: {
            activeCertificatesMap = tDPSPersistenceHandler.getPublishableEntityCertificates();
            break;
        }
        default:
            logger.error("Unknown entityType: {}", entityType);
        }

        return activeCertificatesMap;
    }

    @Override
    public void updateCertificateStatus(final EntityType entityType, final String entityName, final String issuerName, final String serialNumber, final boolean publishedToTDPS)
            throws CertificateException, EntityNotFoundException, IOException, PersistenceException {
        tDPSPersistenceHandler.updateCertificateData(entityType, entityName, issuerName, serialNumber, publishedToTDPS);
    }
}