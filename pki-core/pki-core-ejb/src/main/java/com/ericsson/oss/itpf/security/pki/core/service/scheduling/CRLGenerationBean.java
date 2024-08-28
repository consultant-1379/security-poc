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
package com.ericsson.oss.itpf.security.pki.core.service.scheduling;

import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.CRLManager;

/**
 * This class used to generate CRL for a CertificateAuthority certificate by initializing new transaction for the request.
 * 
 * @author tcskots
 * 
 */
@Stateless
public class CRLGenerationBean {

    @Inject
    private Logger logger;

    @Inject
    private CRLManager crlManager;

    /**
     * This method generates CRL for a certificate of a CertificateAuthority by initializing new transaction
     * 
     * @param certificateAuthorityName
     *            name of the certificateAuthority
     * @param certificate
     *            active/inactive certificate of the certificateAuthority
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void generateCRL(final String certificateAuthorityName, final Certificate certificate) {
        try {
            crlManager.generateCRL(certificateAuthorityName, certificate);
        } catch (Exception e) {
            logger.error(ErrorMessages.AUTOMATIC_CRL_GENERATION_JOB_FAILED, "for CA Certificate {}, {} - {}", certificateAuthorityName, certificate.getSerialNumber(), e.getMessage());
            logger.debug("Automatic CRL generation job failed:", e);
        }
    }

}
