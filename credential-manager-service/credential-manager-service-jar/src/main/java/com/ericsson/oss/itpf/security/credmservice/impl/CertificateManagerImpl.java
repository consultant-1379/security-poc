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
package com.ericsson.oss.itpf.security.credmservice.impl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.CertificateManager;
import com.ericsson.oss.itpf.security.credmservice.api.ExtCACRLManagementInterface;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerAlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateExsitsException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidCSRException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.credmservice.util.CertificateUtils;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.InvalidInvalidityDateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerCertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RootCertificateRevocationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockCACertificateManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockCACrlManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockEntityCertificateManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockEntityManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockExtCACRLManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockExtCACertificateManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockRevocationService;

@Stateless
public class CertificateManagerImpl implements CertificateManager {

    private static final Logger log = LoggerFactory.getLogger(CertificateManagerImpl.class);

    @Inject
    private SystemRecorderWrapper systemRecorder;

    @Inject
    private ContextService ctxService;

    @Inject
    ExtCACRLManagementInterface extCACRLManagement;

    @EServiceRef
    CACertificateManagementService pkiCACertificateManager;

    @EServiceRef
    ExtCACertificateManagementService pkiExtCACertificateManager;

    @EServiceRef
    ExtCACRLManagementService pkiExtCACRLManager;

    @EServiceRef
    CRLManagementService pkiIntCACrlManager;

    @EServiceRef
    EntityCertificateManagementService pkiEntityCertificateManager;

    @EServiceRef
    RevocationService revokeManager;

    @EServiceRef
    MockCACertificateManagementService mockCACertificateManager;

    @EServiceRef
    MockExtCACertificateManagementService mockExtCACertificateManager;

    @EServiceRef
    MockExtCACRLManagementService mockExtCACRLManager;

    @EServiceRef
    MockCACrlManagementService mockIntCACrlManager;

    @EServiceRef
    MockEntityCertificateManagementService mockEntityCertificateManager;

    @EServiceRef
    MockRevocationService mockRevokeManager;

    /* used only for Internal CRL */
    @EServiceRef
    EntityManagementService pkiEntityManager;

    /* used only for Internal CRL */
    @EServiceRef
    MockEntityManagementService mockEntityManager;

    // put here name of interface
    private final String className = this.getClass().getInterfaces()[0].getSimpleName();

    @Override
    public CredentialManagerX509Certificate[] getCertificate(final CredentialManagerPKCS10CertRequest csr, final String entityName,
                                                             final boolean certificateChain, final String otp)
            throws CredentialManagerCertificateEncodingException, CredentialManagerEntityNotFoundException,
            CredentialManagerCertificateGenerationException, CredentialManagerInvalidCSRException, CredentialManagerInvalidEntityException,
            CredentialManagerCertificateExsitsException {

        try {
            Certificate pkiCertificate = null;
            final CertificateRequest pkiRequest = PKIModelMapper.pkiCSRFrom(csr);

            this.systemRecorder.recordCommand("getCertificate", CommandPhase.STARTED, className, entityName, null);
            if (otp == null) {
                pkiCertificate = this.getEntityCertificateManager().generateCertificate(entityName, pkiRequest);
            } else /* we need to verify the OTP as we are in the ENIS/SLS case */
            {
                pkiCertificate = this.getEntityCertificateManager().generateCertificate(entityName, pkiRequest, otp);
            }
            this.systemRecorder.recordCommand("getCertificate", CommandPhase.FINISHED_WITH_SUCCESS, className, entityName, null);

            if (!certificateChain) // single certificate without complete chain
            {
                final CredentialManagerX509Certificate[] certChain = new CredentialManagerX509Certificate[1];
                certChain[0] = PKIModelMapper.credMCertificateFrom(pkiCertificate);
                return certChain;
            }

            // In this case the complete certificate chain is requested, i.e. certificateChain is true:
            final CertificateChain certFullChain = this.getEntityCertificateManager().getCertificateChain(entityName);
            final CredentialManagerX509Certificate[] x509CertFullChain = new CredentialManagerX509Certificate[certFullChain.getCertificates().size()];
            final List<Certificate> certList = certFullChain.getCertificates();
            for (int i = 0; i < certList.size(); i++) {
                // Convert each certificate in the chain from Certificate to CredentialManagerX509Certificate
                final Certificate element = certList.get(i);
                x509CertFullChain[i] = PKIModelMapper.credMCertificateFrom(element);
            }
            return x509CertFullChain;

        } catch (final EntityNotFoundException e) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerEntityNotFoundException(e.getMessage());
        } catch (final CertificateGenerationException e) {
            this.systemRecorder.recordError("CertificateGenerationException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerCertificateGenerationException(e.getMessage());
        } catch (final InvalidCertificateRequestException e) {
            this.systemRecorder.recordError("InvalidCSRException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInvalidCSRException(e.getMessage());
        } catch (final InvalidEntityException e) {
            this.systemRecorder.recordError("InvalidEntityException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException(e.getMessage());
        } catch (final CredentialManagerCertificateEncodingException e) {
            this.systemRecorder.recordError("CredentialManagerCertificateEncodingException", ErrorSeverity.ERROR, className, entityName,
                    e.getMessage());
            throw new CredentialManagerCertificateEncodingException(e.getMessage());
        } catch (final InvalidCAException e) {
            this.systemRecorder.recordError("InvalidCAException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException(e.getMessage());
        } catch (final CertificateServiceException e) {
            this.systemRecorder.recordError("CertificateServiceException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerCertificateGenerationException(e.getMessage());
        } catch (final AlgorithmNotFoundException e) {
            this.systemRecorder.recordError("CertificateGenerationException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerCertificateGenerationException(e.getMessage());
        } catch (final OTPExpiredException e) {
            this.systemRecorder.recordError("CertificateGenerationException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException(e.getMessage());
        } catch (final InvalidOTPException e) {
            this.systemRecorder.recordError("CertificateGenerationException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException(e.getMessage());
        } catch (final ExpiredCertificateException | RevokedCertificateException e) {
            this.systemRecorder.recordError("CertificateGenerationException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerCertificateGenerationException(e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("InvalidEntityAttributeException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException(e.getMessage());
        } catch (final InvalidCertificateStatusException e) {
            this.systemRecorder.recordError("InvalidCertificateStatusException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException(e.getMessage());
        }

    }

    @Override
    public CredentialManagerCertificateAuthority getTrustCertificates(final CredentialManagerTrustCA trustCA, final boolean isExternal)
            throws CredentialManagerInvalidArgumentException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException, CredentialManagerInternalServiceException {

        this.systemRecorder.recordCommand("getTrustCertificates", CommandPhase.STARTED,
                "Credential pki-manager_CrlChain_ActInac/pki-manager-common-jar/src/main/java/com/ericsson/oss/itpf/security/pki/manager/common/persistence/handler/entity/AbstractEntityPersistenceHandler.java:Manager Service",
                trustCA.getTrustCAName(), null);
        final CredentialManagerCertificateAuthority certAuth = new CredentialManagerCertificateAuthority(trustCA.getTrustCAName());
        final List<CredentialManagerX509Certificate> certChainSerializable = new ArrayList<CredentialManagerX509Certificate>();
        try {
            List<CertificateChain> pkiCertificates = new ArrayList<CertificateChain>();
            if (trustCA.getTrustCAName() != null) {
                if (!isExternal) {
                    if (!trustCA.isChainRequired()) {
                        final CertificateChain internalTrust = new CertificateChain();
                        internalTrust.setCertificateChain(this.getCACertificateManager().listCertificates(trustCA.getTrustCAName(),
                                CertificateStatus.ACTIVE, CertificateStatus.INACTIVE));
                        pkiCertificates.add(internalTrust);
                    } else {
                        pkiCertificates = this.getCACertificateManager().getCertificateChainList(trustCA.getTrustCAName(), CertificateStatus.ACTIVE,
                                CertificateStatus.INACTIVE);
                    }
                } else {
                    final CertificateChain externalTrust = new CertificateChain();
                    externalTrust.setCertificateChain(this.getExtCACertificateManager().listCertificates(trustCA.getTrustCAName(),
                            CertificateStatus.ACTIVE, CertificateStatus.INACTIVE));
                    pkiCertificates.add(externalTrust);
                }

                if (pkiCertificates != null && !pkiCertificates.isEmpty()) { //to avoid duplicates for the same trustCA
                    for (final CertificateChain certChain : pkiCertificates) {
                        if (certChain != null && certChain.getCertificates() != null && !certChain.getCertificates().isEmpty()) {
                            for (final Certificate cert : certChain.getCertificates()) {
                                boolean certFound = false;
                                final CredentialManagerX509Certificate credmCert = PKIModelMapper.credMCertificateFrom(cert);
                                for (final CredentialManagerX509Certificate certSer : certChainSerializable) {
                                    if (certSer.retrieveCertificate().getIssuerDN().equals(credmCert.retrieveCertificate().getIssuerDN()) && certSer
                                            .retrieveCertificate().getSerialNumber().equals(credmCert.retrieveCertificate().getSerialNumber())) {
                                        certFound = true;
                                        break;
                                    }
                                }
                                if (certFound) {
                                    continue;
                                }
                                certChainSerializable.add(credmCert);
                            }
                        }
                    }
                }
            }

        } catch (final CredentialManagerCertificateEncodingException e) {
            this.systemRecorder.recordError("CredentialManagerCertificateEncodingException", ErrorSeverity.ERROR, className, trustCA.getTrustCAName(),
                    e.getMessage());
            throw new CredentialManagerCertificateEncodingException(e.getMessage());
        } catch (final CertificateNotFoundException e) {
            this.systemRecorder.recordError("CertificateNotFoundException", ErrorSeverity.ERROR, className, trustCA.getTrustCAName(), e.getMessage());
        } catch (final CertificateServiceException e) {
            this.systemRecorder.recordError("CertificateServiceException", ErrorSeverity.ERROR, className, trustCA.getTrustCAName(), e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final EntityNotFoundException e) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, className, trustCA.getTrustCAName(), e.getMessage());
            throw new CredentialManagerInvalidArgumentException(e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("InvalidEntityAttributeException", ErrorSeverity.ERROR, className, trustCA.getTrustCAName(),
                    e.getMessage());
            throw new CredentialManagerInvalidArgumentException(e.getMessage());
        } catch (final InvalidCAException e) {
            this.systemRecorder.recordError("InvalidCAException", ErrorSeverity.ERROR, className, trustCA.getTrustCAName(), e.getMessage());
            throw new CredentialManagerInvalidArgumentException(e.getMessage());
        } catch (final InvalidCertificateStatusException e) {
            this.systemRecorder.recordError("InvalidCertificateStatusException", ErrorSeverity.ERROR, className, trustCA.getTrustCAName(),
                    e.getMessage());
            throw new CredentialManagerInvalidArgumentException(e.getMessage());
        } catch (final InvalidEntityException e) {
            this.systemRecorder.recordError("InvalidEntityException", ErrorSeverity.ERROR, className, trustCA.getTrustCAName(), e.getMessage());
            throw new CredentialManagerInvalidArgumentException(e.getMessage());
        }
        certAuth.setCertChainSerializable(certChainSerializable);
        this.systemRecorder.recordCommand("getTrustCertificates", CommandPhase.FINISHED_WITH_SUCCESS, className, trustCA.getTrustCAName(), null);
        return certAuth;
    }

    public EntityCertificateManagementService getEntityCertificateManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockCertificateManager()) {
            log.debug("Using Mock PKI EntityCertificateManager");
            return this.mockEntityCertificateManager;
        } else {
            return this.pkiEntityCertificateManager;
        }
    }

    public CACertificateManagementService getCACertificateManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockCertificateManager()) {
            log.debug("Using Mock PKI CACertificateManager");
            return this.mockCACertificateManager;
        } else {
            return this.pkiCACertificateManager;
        }
    }

    public ExtCACertificateManagementService getExtCACertificateManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockCertificateManager()) {
            log.debug("Using Mock PKI CACertificateManager");
            return this.mockExtCACertificateManager;
        } else {
            return this.pkiExtCACertificateManager;
        }

    }

    public ExtCACRLManagementService getExtCACRLManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockExtCACrlManager()) {
            log.debug("Using Mock PKI CACertificateManager");
            return this.mockExtCACRLManager;
        } else {
            log.debug("Using REAL PKI CACertificateManager");
            return this.pkiExtCACRLManager;
        }

    }

    public CRLManagementService getIntCACrlManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockIntCACrlManager()) {
            log.debug("Using Mock PKI CAICrlManager");
            return this.mockIntCACrlManager;
        } else {
            log.debug("Using REAL PKI CAInternalCrlManager");
            return this.pkiIntCACrlManager;

        }
    }

    /*
     * We use flag for Internal CRL because only in case of Internal CRL we need Pki EntityManager or its mock
     */
    public EntityManagementService getIntEntityManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockIntCACrlManager()) {
            log.debug("Using Mock PKI EntityManager");
            return this.mockEntityManager;
        } else {
            log.debug("Using REAL PKI EntitylManager");
            return this.pkiEntityManager;
        }
    }

    public RevocationService getRevokeManager() {

        RBACManagement.injectUserName(ctxService);

        if (PKIMockManagement.useMockCertificateManager()) {
            log.debug("Using Mock PKI RevokeManager");
            return this.mockRevokeManager;
        } else {
            return this.revokeManager;
        }
    }

    /**
     * getCrl
     */
    @Override
    public Map<String, CredentialManagerX509CRL> getCrl(final String caName, final boolean isChainRequired, final boolean isExternal)
            throws CredentialManagerCRLServiceException, CredentialManagerCertificateServiceException, CredentialManagerCRLEncodingException {

        // TODO: the parameter isChainRequired is not yet used
        // it will be used when the PKI will implement the getCRL method

        this.systemRecorder.recordCommand("getCrl", CommandPhase.STARTED, className, caName, null);

        final Map<String, CredentialManagerX509CRL> crlMap = new HashMap<String, CredentialManagerX509CRL>();

        if (!isExternal) {
            if (this.getIntCACrlManager() == null) {

                throw new CredentialManagerCertificateServiceException("PKI not yet implemented for Internal CA");

            }
        } else {
            if (this.getExtCACRLManager() == null) {

                throw new CredentialManagerCertificateServiceException("PKI not yet implemented for External  CA");

            }
        }

        if (caName == null) {
            this.systemRecorder.recordError("CredentialManagerCRLServiceException", ErrorSeverity.ERROR,
                    "Credential Manager Service getCrl CAname empty", null, null);
            throw new CredentialManagerCRLServiceException("ca name received is null");

        }

        if (!isExternal) {
            Map<CACertificateIdentifier, List<CRLInfo>> pkiCrlsMap = null;
            try {

                final CertificateAuthority certificateAuthority = new CertificateAuthority();
                certificateAuthority.setName(caName);
                final CAEntity caEntityToRetrieve = new CAEntity();
                caEntityToRetrieve.setCertificateAuthority(certificateAuthority);

                final CAEntity caEntityRetrieved = this.getIntEntityManager().getEntity(caEntityToRetrieve);

                log.info("Passing for crl for " + caName);

                /*
                 * Manage Active Certificate
                 */
                if (caEntityRetrieved.getCertificateAuthority().getActiveCertificate() != null) {
                    log.info("Calling getCRL for " + caName + " for the active certificate");
                    /*
                     * We invoke PKI getcrl api interface for the active certificate. Therefore pkiCrlsMap map has only one element.
                     *
                     * We invoke PKI getcrl api interface with chain = false. Therefore inside pkiCrlsMap, each element has a List<CRLInfo> that
                     * contains only one element; i.e the latest CRL for the active certificate of the CA with name = caName.
                     *
                     * NOTE : we insert in the returned map only one element with key = caName To AVOID CRL overwrite
                     */
                    pkiCrlsMap = this.getIntCACrlManager().getCRL(caName, CertificateStatus.ACTIVE, isChainRequired);
                    if (pkiCrlsMap != null && pkiCrlsMap.size() == 1) {
                        for (final Map.Entry<CACertificateIdentifier, List<CRLInfo>> entry : pkiCrlsMap.entrySet()) {
                            for (final CRLInfo crlElement : entry.getValue()) {
                                crlMap.put(CertificateUtils.getCN(crlElement.getCrl().getX509CRLHolder().retrieveCRL().getIssuerDN().getName()),
                                        PKIModelMapper.credmX509CRLfrom(crlElement.getCrl().getX509CRLHolder()));
                            }
                        }
                    } else {
                        this.systemRecorder.recordError("CredentialManagerCRLServiceException", ErrorSeverity.ERROR,
                                "Credential Manager Service Internal CA," + "CA with NOT only one active certificate. " + "CA name = ",
                                caName + " Number of active certificates = ", ((Integer) ((pkiCrlsMap != null) ? pkiCrlsMap.size() : 0)).toString());
                        throw new CredentialManagerCRLServiceException(
                                "Invoked PKI getCRL for " + caName + "(certificateStatus = active) and map size received = "
                                        + ((Integer) ((pkiCrlsMap != null) ? pkiCrlsMap.size() : 0)).toString());
                    }
                } else {
                    log.warn("No Active Certificate for " + caName);
                    this.systemRecorder.recordError("No Active Certificate for ", ErrorSeverity.WARNING, null, null, caName);
                }

                /*
                 * Manage Inactive Certificates
                 */
                final List<Certificate> inActiveCertificates = caEntityRetrieved.getCertificateAuthority().getInActiveCertificates();
                if (inActiveCertificates != null && !inActiveCertificates.isEmpty()) {
                    /*
                     * InActiveCertificates List contain certificates with status = INACTIVE, REVOKED and EXPIRED. We are interested only to
                     * certificates with status = INACTIVE
                     */
                    boolean bFoundInActiveStatus = false;
                    for (final Certificate certificate : inActiveCertificates) {
                        if (certificate.getStatus() != null && certificate.getStatus() == CertificateStatus.INACTIVE) {
                            bFoundInActiveStatus = true;
                            break;
                        }
                    }

                    if (bFoundInActiveStatus) {

                        log.debug("Calling getCRL for {} for the inactive certificates", caName);
                        /*
                         * We invoke PKI getcrl api interface for the inactive certificate. Therefore pkiCrlsMap may have many elements (from 0 to
                         * ...).
                         *
                         * We invoke PKI getcrl api interface with chain = false. Therefore inside pkiCrlsMap, each element has a List<CRLInfo> that
                         * contains only one element; i.e the latest CRL for one of the inactive certificates of the CA with name = caName.
                         *
                         * NOTE : we insert in the returned map more elements; each element has a key = caName_SerialNumber.
                         */
                        pkiCrlsMap = this.getIntCACrlManager().getCRL(caName, CertificateStatus.INACTIVE, isChainRequired);
                        if (pkiCrlsMap != null && !pkiCrlsMap.isEmpty()) {
                            for (final Map.Entry<CACertificateIdentifier, List<CRLInfo>> entry : pkiCrlsMap.entrySet()) {
                                for (final CRLInfo crlElement : entry.getValue()) {
                                    if (crlElement.getIssuerCertificate().getStatus() == CertificateStatus.INACTIVE) {
                                        crlMap.put(
                                                CertificateUtils.getCN(crlElement.getCrl().getX509CRLHolder().retrieveCRL().getIssuerDN().getName())
                                                        + "_" + crlElement.getIssuerCertificate().getSerialNumber(),
                                                PKIModelMapper.credmX509CRLfrom(crlElement.getCrl().getX509CRLHolder()));
                                    }
                                }
                            }
                        }
                    } else {
                        log.info("No Certificates with InActive Status for " + caName);
                    }

                } else {
                    log.info("No InActive Certificates for " + caName);
                }

            } catch (CertificateNotFoundException | CANotFoundException | CRLServiceException | InvalidCertificateStatusException
                    | EntityNotFoundException | EntityServiceException | UnsupportedOperationException | ClassCastException | NullPointerException
                    | IllegalArgumentException | InvalidEntityException | InvalidEntityAttributeException
                    | CredentialManagerCertificateEncodingException e) {

                this.systemRecorder.recordError("CredentialManagerCRLServiceException", ErrorSeverity.ERROR, "Credential Manager Service Internal CA",
                        caName, e.getMessage());
                throw new CredentialManagerCRLServiceException(e.getMessage());
            }

        } else {
            try {
                log.debug("List CRL for ext CA {}", caName);
                final List<ExternalCRLInfo> externalCRLInfos = listExternalCRLInfo(caName);
                for (final ExternalCRLInfo externalCRLInfo : externalCRLInfos) {
                    String crlName = caName + "_";
                    crlName += CertificateUtils.getCN(externalCRLInfo.getX509CRL().retrieveCRL().getIssuerDN().getName());
                    crlMap.put(crlName, PKIModelMapper.credMCrlFrom(externalCRLInfo));
                }
            } catch (final ExternalCRLNotFoundException e) {
                log.info("CRLs not found for External CA {}", caName);
            } catch (UnsupportedOperationException | ClassCastException | MissingMandatoryFieldException | NullPointerException
                    | IllegalArgumentException | ExternalCANotFoundException | ExternalCredentialMgmtServiceException | ExternalCRLEncodedException
                    | CredentialManagerCRLEncodingException e) {
                this.systemRecorder.recordError("CredentialManagerExternalCRLServiceException", ErrorSeverity.ERROR,
                        "Credential Manager Service External CA", caName, e.getMessage());
                throw new CredentialManagerCRLServiceException(e.getMessage());
            }
        }
        this.systemRecorder.recordCommand("getCrl", CommandPhase.FINISHED_WITH_SUCCESS, className, caName, null);

        return crlMap;

    }//end of getCrl

    /**
     * @param caName
     * @return
     */
    private List<ExternalCRLInfo> listExternalCRLInfo(final String caName) {
        RBACManagement.injectUserName(ctxService);
        List<ExternalCRLInfo> externalCRLInfos = null;
        if (PKIMockManagement.useMockExtCACrlManager()) {
            log.debug("Using Mock PKI ExtCACRLManager");
            externalCRLInfos =  this.mockExtCACRLManager.listExternalCRLInfo(caName);
        } else {
            log.debug("Using REAL PKI ExtCACRLManager");
            externalCRLInfos = this.extCACRLManagement.listExternalCRLInfo(caName);
        }
        return externalCRLInfos;
    }

    /**
     * RevokeCertificateByEntity
     */
    @Override
    public void RevokeCertificateByEntity(final String entityName, final CredentialManagerRevocationReason revocationReason,
                                          final Date invalidityDate)
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException {

        if (entityName == null || entityName.isEmpty()) {
            throw new CredentialManagerEntityNotFoundException("EntityName cannot be null!");
        }

        final RevocationReason reason = RevocationReason.fromValue(revocationReason.value());

        try {
            this.getRevokeManager().revokeEntityCertificates(entityName, reason, invalidityDate);
        } catch (final EntityNotFoundException e) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerEntityNotFoundException(e.getMessage());
        } catch (final RootCertificateRevocationException e) {
            this.systemRecorder.recordError("RootCertificateRevocationException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final ExpiredCertificateException e) {
            this.systemRecorder.recordError("ExpiredCertificateException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final RevokedCertificateException e) {
            this.systemRecorder.recordError("RevokedCertificateException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final CertificateNotFoundException e) {
            log.info("CertificateNotFound " + e);
            //this.systemRecorder.recordError("CertificateNotFoundException", ErrorSeverity.INFORMATIONAL, className, entityName, e.getMessage());
            //throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final RevocationServiceException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final EntityAlreadyExistsException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerEntityNotFoundException(e.getMessage());
        } catch (final InvalidInvalidityDateException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final IssuerCertificateRevokedException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        }
    }

    /**
     * RevokeCertificateById
     *
     * @param credMCertificateIdentifier
     * @param revocationReason
     * @param invalidityDate
     * @throws CredentialManagerCertificateNotFoundException
     * @throws CredentialManagerCertificateServiceException
     * @throws CredentialManagerExpiredCertificateException
     * @throws CredentialManagerAlreadyRevokedCertificateException
     */
    @Override
    public void RevokeCertificateById(final CredentialManagerCertificateIdentifier credMCertificateIdentifier,
                                      final CredentialManagerRevocationReason revocationReason, final Date invalidityDate)
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerExpiredCertificateException, CredentialManagerAlreadyRevokedCertificateException {

        final RevocationReason reason = RevocationReason.fromValue(revocationReason.toString());

        final DNBasedCertificateIdentifier dnBaseCertId = new DNBasedCertificateIdentifier();
        dnBaseCertId.setIssuerDN(credMCertificateIdentifier.getIssuerDN().getName());
        dnBaseCertId.setSubjectDN(credMCertificateIdentifier.getSubjectDN().getName());
        dnBaseCertId.setCerficateSerialNumber(credMCertificateIdentifier.getSerialNumber().toString(16));

        log.info("DNBasedCertificateIdentifier: Issuer DN = " + dnBaseCertId.getIssuerDN());
        log.info("DNBasedCertificateIdentifier: Subject DN = " + dnBaseCertId.getSubjectDN());
        log.info("DNBasedCertificateIdentifier: Cert Serial Number = " + dnBaseCertId.getCerficateSerialNumber());

        try {
            this.getRevokeManager().revokeCertificateByDN(dnBaseCertId, reason, invalidityDate);
        } catch (final EntityNotFoundException e) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerCertificateNotFoundException(e.getMessage());
        } catch (final RootCertificateRevocationException e) {
            this.systemRecorder.recordError("RootCertificateRevocationException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerCertificateServiceException(e.getMessage());
        } catch (final ExpiredCertificateException e) {
            this.systemRecorder.recordError("ExpiredCertificateException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerExpiredCertificateException(e.getMessage());
        } catch (final RevokedCertificateException e) {
            this.systemRecorder.recordError("RevokedCertificateException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerAlreadyRevokedCertificateException(e.getMessage());
        } catch (final CertificateNotFoundException e) {
            this.systemRecorder.recordError("CertificateNotFoundException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerCertificateNotFoundException(e.getMessage());
        } catch (final RevocationServiceException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerCertificateServiceException(e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerCertificateServiceException(e.getMessage());
        } catch (final InvalidInvalidityDateException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerCertificateServiceException(e.getMessage());
        } catch (final IssuerCertificateRevokedException e) {
            this.systemRecorder.recordError("RevocationServiceException", ErrorSeverity.ERROR, className,
                    credMCertificateIdentifier.getSubjectDN().getName(), e.getMessage());
            throw new CredentialManagerCertificateServiceException(e.getMessage());
        }
    }

    /**
     * ListCertificates
     */
    @Override
    public List<CredentialManagerX509Certificate> ListCertificates(final String entityName, final CredentialManagerEntityType entityType,
                                                                   final CredentialManagerCertificateStatus... credMCertStatus)
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException {

        final List<Certificate> certsList = getPkiCertsListByEntityNameAndCertsStatus(entityName, entityType, credMCertStatus);

        final List<CredentialManagerX509Certificate> x509CertsList = new ArrayList<CredentialManagerX509Certificate>();

        for (int i = 0; i < certsList.size(); i++) {
            // Convert each certificate in the chain from Certificate to CredentialManagerX509Certificate
            final Certificate element = certsList.get(i);
            try {
                x509CertsList.add(PKIModelMapper.credMCertificateFrom(element));
            } catch (final CredentialManagerCertificateEncodingException e) {
                this.systemRecorder.recordError("CredentialManagerCertificateEncodingException", ErrorSeverity.ERROR, className, entityName,
                        e.getMessage());
                throw new CredentialManagerCertificateEncodingException(e.getMessage());
            }
        }

        return x509CertsList;
    }

    /**
     * @param entityName
     * @param entityType
     * @param credMCertStatus
     * @return
     */
    private List<Certificate> getPkiCertsListByEntityNameAndCertsStatus(final String entityName, final CredentialManagerEntityType entityType,
                                                                        final CredentialManagerCertificateStatus... credMCertStatus)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCertificateNotFoundException,
            CredentialManagerCertificateServiceException, CredentialManagerEntityNotFoundException {
        if (entityName == null || entityName.isEmpty()) {
            this.systemRecorder.recordError("CredentialManagerInvalidArgumentException", ErrorSeverity.ERROR, className, entityName, null);
            throw new CredentialManagerInvalidArgumentException("EntityName cannot be null!");
        }

        if (credMCertStatus == null || credMCertStatus.length == 0) {
            this.systemRecorder.recordError("CredentialManagerInvalidArgumentException", ErrorSeverity.ERROR, className, entityName, null);
            throw new CredentialManagerInvalidArgumentException("Certificate Status cannot be null!");
        }

        List<Certificate> certsList = new ArrayList<Certificate>();
        final CertificateStatus[] certStatusArray = new CertificateStatus[credMCertStatus.length];

        //CertificateStatus conversion
        for (int i = 0; i < credMCertStatus.length; i++) {
            certStatusArray[i] = CertificateStatus.fromValue(credMCertStatus[i].value());
        }

        try {
            if (entityType == CredentialManagerEntityType.CA_ENTITY) {
                certsList = this.getCACertificateManager().listCertificates(entityName, certStatusArray);
            } else if (entityType == CredentialManagerEntityType.ENTITY) {
                certsList = this.getEntityCertificateManager().listCertificates(entityName, certStatusArray);
            } else {
                throw new CredentialManagerInvalidArgumentException("EntityType can only be CA_ENTITY or ENTITY!");
            }
        } catch (final CertificateNotFoundException e) {
            this.systemRecorder.recordError("CredentialManagerCertificateNotFoundException", ErrorSeverity.ERROR, className, entityName,
                    e.getMessage());
            throw new CredentialManagerCertificateNotFoundException(e.getMessage());
        } catch (final CertificateServiceException e) {
            this.systemRecorder.recordError("CredentialManagerCertificateServiceException", ErrorSeverity.ERROR, className, entityName,
                    e.getMessage());
            throw new CredentialManagerCertificateServiceException(e.getMessage());
        } catch (final EntityNotFoundException e) {
            this.systemRecorder.recordError("CredentialManagerEntityNotFoundException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerEntityNotFoundException(e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, className, entityName, e.getMessage());
            throw new CredentialManagerInvalidArgumentException(e.getMessage());
        }
        return certsList;
    }

    @Override
    public void printCommandOnRecorder(final String message, final CommandPhase category, final String source, final String entityName,
                                       final String infos) {

        this.systemRecorder.recordCommand(message, category, source, entityName, infos);
    }

    @Override
    public void printErrorOnRecorder(final String message, final ErrorSeverity category, final String source, final String entityName,
                                     final String infos) {

        this.systemRecorder.recordError(message, category, source, entityName, infos);
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmservice.api.CertificateManager#listCertificatesSummary(java.lang.String,
     * com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType,
     * com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus[])
     */
    @Override
    public List<CredentialManagerX500CertificateSummary> listCertificatesSummary(final String entityName,
                                                                                 final CredentialManagerEntityType entityType,
                                                                                 final CredentialManagerCertificateStatus... credMCertStatus)
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException {

        final List<Certificate> certsList = getPkiCertsListByEntityNameAndCertsStatus(entityName, entityType, credMCertStatus);

        final List<CredentialManagerX500CertificateSummary> x500CertsSummaryList = new ArrayList<CredentialManagerX500CertificateSummary>();

        for (int i = 0; i < certsList.size(); i++) {
            // from each certificate retrieved from PKI a CredentialManagerX500CertificateSummary structure is built.
            final Certificate element = certsList.get(i);
            try {

                final CredentialManagerX500CertificateSummary credentialManagerx500CertSummary = new CredentialManagerX500CertificateSummary();
                final CredentialManagerX509Certificate credentialManagerx509Certificate = PKIModelMapper.credMCertificateFrom(element);
                final CertificateStatus pkiCertificateStatus = element.getStatus();
                final CredentialManagerCertificateStatus credManCertStatus = CredentialManagerCertificateStatus
                        .fromValue(pkiCertificateStatus.value().toUpperCase());
                final X509Certificate x509Certificate = credentialManagerx509Certificate.retrieveCertificate();

                credentialManagerx500CertSummary.setCertificateSN(x509Certificate.getSerialNumber());
                credentialManagerx500CertSummary.setIssuerX500Principal(x509Certificate.getIssuerX500Principal());
                credentialManagerx500CertSummary.setSubjectX500Principal(x509Certificate.getSubjectX500Principal());
                credentialManagerx500CertSummary.setCertificateStatus(credManCertStatus);

                /*
                 * DEBUG
                 */
                if (log.isDebugEnabled()) {
                    log.debug("listCertificatesSummary; retrieved from PKI : issuerDN = {}; subjectDN = {}; certificateSN = {}; cert Status = {}",
                            credentialManagerx500CertSummary.getIssuerX500Principal().getName(),
                            credentialManagerx500CertSummary.getSubjectX500Principal().getName(), credentialManagerx500CertSummary.getCertificateSN(),
                            credentialManagerx500CertSummary.getCertificateStatus().value());
                }
                x500CertsSummaryList.add(credentialManagerx500CertSummary);

            } catch (final Exception e) {
                this.systemRecorder.recordError("CredentialManagerCertificateEncodingException", ErrorSeverity.ERROR, className, entityName,
                        e.getMessage());
                throw new CredentialManagerCertificateEncodingException(e.getMessage());
            }
        }

        return x500CertsSummaryList;
    }
    //DU: Fallback solution for PKI External CA
    //    private Map<String, CredentialManagerX509CRL> getCRLsFromFile() throws CredentialManagerCRLServiceException {
    //
    //        final Map<String, CredentialManagerX509CRL> caCrls = new HashMap<String, CredentialManagerX509CRL>();
    //
    //        final String[] extSubCANames = PKIExtCAManagementFallbackSolution.getExtSubCAName();
    //        if (extSubCANames != null) {
    //            final String extCAPath = PKIExtCAManagementFallbackSolution.getExtCAPath();
    //            for (final String subCAName : extSubCANames) {
    //                InputStream crlFile = null;
    //                try {
    //                    if (extCAPath != null) {
    //                        final String fileName = extCAPath + "/" + subCAName + ".crl";
    //                        crlFile = new FileInputStream(fileName);
    //                    } else {
    //                        crlFile = CertificateManagerImpl.class.getClassLoader().getResourceAsStream(subCAName + ".crl");
    //                    }
    //                } catch (final FileNotFoundException e) {
    //                    throw new CredentialManagerCRLServiceException(e.getMessage());
    //                }
    //                if (crlFile != null) {
    //                    try {
    //                        final X509CRLHolder crlHolder = new X509CRLHolder(crlFile);
    //                        caCrls.put(subCAName, PKIModelMapper.credmX509CRLfrom(crlHolder));
    //                    } catch (final IOException e) {
    //                        throw new CredentialManagerCRLServiceException(e.getMessage());
    //                    }
    //                }
    //
    //            }
    //        }
    //        return caCrls;
    //    }

} // end of file
