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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import java.util.EnumSet;

import javax.ejb.*;
import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementCoreLocalService;

/**
 * This is a local ejb class for CRLManagementService. It is used to provide new transaction if a request is not associated with any transaction.
 * 
 * @author xramdag
 */
@Stateless
public class CRLManagementCoreLocalServiceBean implements CRLManagementCoreLocalService {

    @EServiceRef
    private CRLManagementService coreCRLManagementService;

    @Inject
    private CertificatePersistenceHelper certificatePersistenceHelper;

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public CRLInfo generateCrl(final CACertificateIdentifier caCertIdentifier) throws CertificateNotFoundException, CertificateExpiredException, CertificateRevokedException,
            CoreEntityNotFoundException, CRLGenerationException, CRLGenerationInfoNotFoundException, CRLServiceException, ExpiredCertificateException, InvalidCAException,
            InvalidCRLExtensionException, InvalidCRLGenerationInfoException, InvalidCoreEntityAttributeException, RevokedCertificateException {
        certificatePersistenceHelper.validateCertificateChain(caCertIdentifier, EnumSet.of(CertificateStatus.REVOKED, CertificateStatus.EXPIRED));
        CRLInfo crlInfo = null;
        try {
            crlInfo = coreCRLManagementService.generateCRL(caCertIdentifier);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException e) {
            throw new CertificateNotFoundException(e.getMessage());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException e) {
            throw new CANotFoundException(e.getMessage(), e);
        }
        return crlInfo;
    }
}
