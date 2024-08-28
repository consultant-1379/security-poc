package com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.service;

import java.util.List;
import java.util.Map;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;

/**
 * Implementation of {@link CRLManagementService}
 *
 */
@Profiled
@Stateless
public class CRLManagementServiceBean implements CRLManagementService {

    @Inject
    CRLManager crlManager;

    @Inject
    Logger logger;

    @Override
    public CRLInfo generateCRL(final CACertificateIdentifier caCertificateIdentifier) throws CertificateExpiredException, CertificateRevokedException, CertificateNotFoundException,
            CoreEntityNotFoundException, CRLServiceException, CRLGenerationException, InvalidCoreEntityAttributeException, RevocationServiceException {
        final CRLInfo crlInfo = crlManager.generateCRL(caCertificateIdentifier);
        return crlInfo;
    }

    @Override
    public List<CRLInfo> getAllCRLs(final CACertificateIdentifier caCertificateIdentifier) throws CertificateNotFoundException, CoreEntityNotFoundException, CRLServiceException, InvalidCAException {
        logger.debug("Fetching all CRLs for CaEntity {} ", caCertificateIdentifier.getCaName());
        final List<CRLInfo> crlList = crlManager.getAllCRLs(caCertificateIdentifier);
        return crlList;
    }

    @Override
    public Map<CACertificateIdentifier, CRLInfo> getLatestCRLs(final List<CACertificateIdentifier> caCertificateIdentifierList) throws CRLServiceException {
        logger.debug("Fetching LATEST CRLs for {} caCertificateIdentifier objects " , caCertificateIdentifierList.size());
        final Map<CACertificateIdentifier, CRLInfo> latestCRLsMap = crlManager.getLatestCRLs(caCertificateIdentifierList);
        return latestCRLsMap;
    }

    @Override
    public void updateCRLStatusToExpired() throws CRLServiceException {
        crlManager.updateCRLStatusToExpired();
    }

    @Override
    public void updateCRLStatusToInvalid() throws CRLServiceException {
        crlManager.updateCRLStatusToInvalid();
    }

    @Override
    public CRLInfo getCRL(final String caEntityName, final CRLNumber crlNumber) throws CoreEntityNotFoundException, CRLNotFoundException, CRLServiceException, InvalidCAException {
        logger.debug("get CRL By CAName and CRLNumber,caName received as{}", caEntityName);
        return crlManager.getCRL(caEntityName, crlNumber);
    }

    @Override
    public Map<CACertificateIdentifier, List<CRLInfo>> getAllCRLs(final String caEntityName, final CertificateStatus certificateStatus) throws CertificateNotFoundException,
            CoreEntityNotFoundException, CRLServiceException, InvalidCAException {
        logger.debug("Fetching all CRLs for CA {} with a certificate having status{} ", caEntityName, certificateStatus);
        final Map<CACertificateIdentifier, List<CRLInfo>> crlInfoMap = crlManager.getAllCRLs(caEntityName, certificateStatus);
        return crlInfoMap;
    }
}
