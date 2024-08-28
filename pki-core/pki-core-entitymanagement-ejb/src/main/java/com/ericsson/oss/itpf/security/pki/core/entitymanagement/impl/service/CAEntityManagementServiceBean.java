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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.api.CAEntityManagementService;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.CAEntityManager;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

@Profiled
@Stateless
public class CAEntityManagementServiceBean implements CAEntityManagementService {

    @Inject
    CAEntityManager cAEntityManager;

    @Inject
    Logger logger;

    @EJB
    BulkImportLocalServiceBean bulkImportLocalServiceBean;

    @Override
    public CertificateAuthority updateCA(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityNotFoundException, CoreEntityServiceException,
            InvalidCoreEntityAttributeException {

        final CertificateAuthority certAuthority = cAEntityManager.updateCA(certificateAuthority);

        logger.debug("Updated {}", certificateAuthority.getName());

        return certAuthority;
    }

    @Override
    public CertificateAuthority createCA(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, InvalidCoreEntityAttributeException {

        final CertificateAuthority certAuthority = cAEntityManager.createCA(certificateAuthority);

        logger.debug("Created {}", certificateAuthority.getName());

        return certAuthority;
    }

    @Override
    public void deleteCA(final CertificateAuthority certificateAuthority) throws CoreEntityInUseException, CoreEntityNotFoundException, CoreEntityServiceException {

        cAEntityManager.deleteCA(certificateAuthority);

        logger.debug("Deleted {}", certificateAuthority.getName());
    }

    @Override
    public List<CertificateAuthority> importCAEntities(final List<CertificateAuthority> certificateAuthorityList) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        bulkImportLocalServiceBean.importCertificateAuthority(certificateAuthorityList);
        return certificateAuthorityList;
    }

}
