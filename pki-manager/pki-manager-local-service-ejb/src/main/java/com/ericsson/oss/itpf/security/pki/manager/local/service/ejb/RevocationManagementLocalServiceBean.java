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

import java.util.Date;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.RevocationManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.RevocationManagementLocalService;

@Stateless
public class RevocationManagementLocalServiceBean implements RevocationManagementLocalService {

    @Inject
    RevocationManager revocationManager;

    @Inject
    private ContextUtility contextUtility;

    /**
     * This method provides implementation for revokeCertificate method.
     */
    @Override
    public void revokeCertificate(final CertificateIdentifier certificateIdentifier, final Date invalidityDate, final RevocationReason revocationReason, final String transactionId,
            final String senderName) throws CertificateNotFoundException, EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException,
            InvalidInvalidityDateException, IssuerCertificateRevokedException, IssuerNotFoundException, RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {
        contextUtility.setInternalContext();
        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, revocationReason, invalidityDate);
    }

}
