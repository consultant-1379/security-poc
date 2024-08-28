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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl;

import java.util.*;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.rest.CertificateManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.CertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.CertificateManagementServiceLocal;

@Stateless
public class CertificateManagementServiceLocalBean implements CertificateManagementServiceLocal {

    @Inject
    CertificateManager certificateManager;

    @Inject
    CertificateManagementAuthorizationHandler certificateManagementAuthorizationHandler;

    @Inject
    Logger logger;

    @Override
    public List<Certificate> getCertificates(final CertificateFilter certificateFilter) throws CertificateException, CertificateServiceException {

        authorizeReadOperations(certificateFilter);
        logger.debug("Get Certificates by CertificateFilter {} ", certificateFilter);

        final List<Certificate> certificateList = certificateManager.getCertificates(certificateFilter);

        logger.debug(" Listed Certificates by CertificateFilter");

        return certificateList;
    }

    @Override
    public long getCertificateCount(final CertificateFilter certificateFilter) throws CertificateException, CertificateServiceException {

        authorizeReadOperations(certificateFilter);
        logger.debug("Get Certificates Count by CertificateFilter {} ", certificateFilter);

        final long certificatesCount = certificateManager.getCertificateCount(certificateFilter);

        logger.debug("Certificates Count by CertificateFilter {} ", certificatesCount);

        return certificatesCount;
    }

    /**
     * This method authorizes the operations to be performed according to the user's role.
     * 
     * @param certificateFilter
     */
    private void authorizeReadOperations(final CertificateFilter certificateFilter) {
        List<EntityType> entityTypes = new ArrayList<EntityType>();
        if (certificateFilter.getEntityTypes() == null || certificateFilter.getEntityTypes().length == 0) {
            //adding default values in case of default filter
            entityTypes.add(EntityType.CA_ENTITY);
            entityTypes.add(EntityType.ENTITY);
        } else {
            entityTypes = new ArrayList<EntityType>(Arrays.asList(certificateFilter.getEntityTypes()));
        }
        final Iterator<EntityType> iterator = entityTypes.iterator();
        while (iterator.hasNext()) {
            try {
                switch (iterator.next()) {
                case CA_ENTITY: {
                    certificateManagementAuthorizationHandler.authorizeListCACerts();
                    break;
                }
                case ENTITY: {
                    certificateManagementAuthorizationHandler.authorizeListEntityCerts();
                    break;
                }
                }
            } catch (final SecurityViolationException e) {
                logger.debug("Security Violation occured ", e);
                iterator.remove();
            }
        }
        if (ValidationUtils.isNullOrEmpty(entityTypes)) {
            logger.error("User is Not authorized to perform operation");
            throw new SecurityViolationException("access control decision: denied to invoke: read on resource: reading Certificates");
        }
        certificateFilter.setEntityTypes(entityTypes.toArray(new EntityType[0]));
    }
}
