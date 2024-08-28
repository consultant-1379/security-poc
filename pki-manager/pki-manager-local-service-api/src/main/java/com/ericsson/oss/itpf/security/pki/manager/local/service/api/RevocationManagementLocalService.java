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
package com.ericsson.oss.itpf.security.pki.manager.local.service.api;

import java.util.Date;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * This class provides interface to Revoke certificate.
 *
 * @author tcsramc
 *
 */
@EService
@Local
public interface RevocationManagementLocalService {
    /**
     * This method is used to revoke the certificate.
     *
     * @param certificateIdentifier
     *            from which issuername and serial number has to be fetched.
     * @param invalidityDate
     *            date from which certificate become invalid.
     * @param revocationReason
     *            reason for revoking the certificate
     * @param transactionId
     *            unique id to identify the transaction.
     * @param senderName
     *            subject name.
     * @throws ExpiredCertificateException
     *             is thrown if the certificate is expired.
     * @throws RevokedCertificateException
     *             is thrown if any error occurs while revoking the certificate.
     */
    void revokeCertificate(final CertificateIdentifier certificateIdentifier, final Date invalidityDate, final RevocationReason revocationReason, final String transactionId, final String senderName)
            throws  CertificateNotFoundException, EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException,
            InvalidInvalidityDateException, IssuerCertificateRevokedException, IssuerNotFoundException, RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException;
}
