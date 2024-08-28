/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb.custom;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.CertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.custom.EntityCertificateManagementCustomService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.SecGwCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.exception.EntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.ProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.custom.secgw.SecGWCertificates;

@Profiled
@Stateless
@ErrorLogAnnotation()
public class EntityCertificateManagementCustomServiceBean implements EntityCertificateManagementCustomService {

    @Inject
    Logger logger;

    @Inject
    CertificateManagementAuthorizationManager certificateManagementAuthorizationManager;

    @Inject
    SecGwCertificateManager secGwCertificateManager;

    @Override
    public SecGWCertificates generateSecGWCertificate(final String entityName, final CertificateRequest certificateRequest,
            final Boolean isChainRequired) throws AlgorithmNotFoundException, CertificateException, EntityException, IllegalArgumentException,
            InvalidCertificateRequestException, ProfileException {

        certificateManagementAuthorizationManager.authorizeGenerateSecGwCertificate();

        logger.info("generating certificate for security gateway {} with CSR as input", entityName);

        return secGwCertificateManager.generateSecGwCertificate(entityName, certificateRequest, isChainRequired, RequestType.NEW);
    }
}
