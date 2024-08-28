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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb;

import java.util.List;
import java.util.Map;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExtCACRLManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.ExtCACRLManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.CRLGenerationStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.cdps.CRLPublishUnpublishStatus;

@Profiled
@Stateless
@EServiceQualifier("1.0.0")
@ErrorLogAnnotation()
public class ExtCACRLManagementServiceBean implements ExtCACRLManagementService {

    @Inject
    Logger logger;

    @Inject
    ExtCACRLManager extCACRLManager;

    @Inject
    ExtCACRLManagementAuthorizationManager extCACRLManagementAuthorizationManager;

    @Override
    public void addExternalCRLInfo(final String extCAName, final ExternalCRLInfo crl) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCRLEncodedException, ExternalCRLException,
            ExternalCredentialMgmtServiceException {
        extCACRLManagementAuthorizationManager.authorizeExternalCRLOperations(ActionType.UPDATE);
        extCACRLManager.addCRL(extCAName, crl);
    }

    @Override
    public void configExternalCRLInfo(final String extCAName, final Boolean isCrlAutoUpdateEnabled, final Integer crlAutoUpdateTimer) throws MissingMandatoryFieldException,
            ExternalCANotFoundException, ExternalCredentialMgmtServiceException {
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.UPDATE);
        extCACRLManager.configCRLInfo(extCAName, isCrlAutoUpdateEnabled, crlAutoUpdateTimer);
    }

    @Override
    public List<ExternalCRLInfo> listExternalCRLInfo(final String extCAName) throws MissingMandatoryFieldException, ExternalCRLNotFoundException, ExternalCANotFoundException,
            ExternalCredentialMgmtServiceException, ExternalCRLEncodedException {
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.READ);
        return extCACRLManager.listExternalCRLInfo(extCAName);
    }

    @Override
    public void remove(final String extCAName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCAInUseException, ExternalCredentialMgmtServiceException {
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.DELETE);
        extCACRLManager.removeAllCRLs(extCAName);
    }

    @Override
    public void removeExtCRL(final String extCAName, final String issuerName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCRLNotFoundException,
            ExternalCredentialMgmtServiceException {
        extCACRLManagementAuthorizationManager.authorizeExternalCRLInfoOperations(ActionType.DELETE);
        extCACRLManager.removeCRLs(extCAName, issuerName);
    }

    @Override
    public void generateCRL(final CACertificateIdentifier caCertIdentifier) throws CANotFoundException, CertificateNotFoundException, CRLGenerationException, CRLServiceException,
            ExpiredCertificateException, RevokedCertificateException {
    }

    @Override
    public CRLInfo getCRLByCACertificate(final CACertificateIdentifier caCertIdentifier) throws CANotFoundException, CertificateNotFoundException, CRLNotFoundException, CRLServiceException,
            ExpiredCertificateException, RevokedCertificateException {

        return null;
    }

    @Override
    public List<CRLInfo> getAllCRLs(final CACertificateIdentifier caCertIdentifier) throws CANotFoundException, CertificateNotFoundException, CRLNotFoundException, CRLServiceException {

        return null;
    }

    @Override
    public Map<CACertificateIdentifier, List<CRLInfo>> getCRL(final String caEntityName, final CertificateStatus certificateStatus, final boolean isChainRequired) throws CANotFoundException,
            CertificateNotFoundException, InvalidCertificateStatusException, CRLServiceException {
        return null;
    }

    @Override
    public CRLInfo getCRL(final String arg0, final CRLNumber arg1) throws CANotFoundException, CRLNotFoundException, CRLServiceException {
        return null;
    }

    @Override
    public Map<String, CRLPublishUnpublishStatus> publishCRLToCDPS(final List<String> arg0) throws CRLServiceException {
        return null;
    }

    @Override
    public Map<String, CRLPublishUnpublishStatus> unpublishCRLFromCDPS(final List<String> arg0) throws CRLServiceException {
        return null;
    }

    @Override
    public Map<CACertificateIdentifier, CRLGenerationStatus> generateCRL(final List<String> caEntityNameList, final CertificateStatus... certificateStatus) throws InvalidCertificateStatusException {
        return null;
    }

    @Override
    public Map<CACertificateIdentifier, List<CRLInfo>> getAllCRLs(final String caEntityName, final CertificateStatus certificateStatus) throws CANotFoundException, CertificateNotFoundException,
            CRLServiceException {
        return null;
    }
}
