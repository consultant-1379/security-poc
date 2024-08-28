/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.ejb;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.api.CertificateManager;
import com.ericsson.oss.itpf.security.credmservice.api.CertificateManagerPki;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;

@Stateless
public class CertificateManagerPkiBean implements CertificateManagerPki {

    private static final Logger logger = LoggerFactory.getLogger(CertificateManagerPkiBean.class);

    @Inject
    CertificateManager certificateManager;

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public CredentialManagerCertificateAuthority getTrustCertificates(final CredentialManagerTrustCA caName, final boolean isExternal) {
        try {
            return certificateManager.getTrustCertificates(caName, isExternal);
        } catch (final CertificateNotFoundException ex) {
            logger.warn("Got CertificateNotFoundException");
            throw ex;
        }
    }

}
