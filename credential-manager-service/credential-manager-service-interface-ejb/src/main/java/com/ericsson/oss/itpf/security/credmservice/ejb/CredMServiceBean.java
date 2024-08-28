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

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.CertificateManager;
import com.ericsson.oss.itpf.security.credmservice.api.CertificateManagerPki;
import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.ProfileManager;
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
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerOtpExpiredException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCALists;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.configuration.listener.CredentialManagerConfigurationListener;
import com.ericsson.oss.itpf.security.credmservice.util.CertificateUtils;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;

@Stateless
public class CredMServiceBean implements CredMService {

    /**
     * Version of CredMService interface.
     */
    static final String FILE_PROPERTIES = "/ericsson/credm/service/data/version.properties";

    static final String VERSION_PROPERTIES = "version";

    public String CMSERVICE_VERSION;
    private static final Logger log = LoggerFactory.getLogger(CredMServiceBean.class);

    @Inject
    private ProfileManager profileManager;
    @Inject
    private CertificateManager certificateManager;
    @Inject
    private CertificateManagerPki certificateManagerPki;
    @Inject
    CredMRestAvailability credMPkiConfBean;
    @Inject
    CredentialManagerConfigurationListener credentialManagerConfigurationListener;

    @Override
    public String hello(final String msg) {

        log.info(msg);

        return "Hi " + msg + ", nice to meet you, I'm Credential Manager Service";
    }

    @Override
    public CredentialManagerEntity createAndGetEntity(final String entityName, final CredentialManagerSubject subject,
            final CredentialManagerSubjectAltName subjectAltName,
            final CredentialManagerAlgorithm keyGenerationAlgorithm, final String entityProfileName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException,
            CredentialManagerProfileNotFoundException {

        CredentialManagerEntity entity = null;

        final boolean entityExists = profileManager.isEntityPresent(CertificateUtils.getCN(entityName));
        if (entityExists) {
            try {
                entity = profileManager.updateEntity(CertificateUtils.getCN(entityName), subject, subjectAltName, keyGenerationAlgorithm,
                        entityProfileName);
            } catch (final CredentialManagerEntityNotFoundException e) {
                log.debug("Entity: {} not found. Something is wrong because it was present before.", entityName);
                log.debug("updateEntity exception {}", e);
            }
        } else {
            entity = profileManager.createEntity(CertificateUtils.getCN(entityName), subject, subjectAltName, keyGenerationAlgorithm,
                    entityProfileName);
        }
        return entity;
    }

    @Override
    public CredentialManagerEntity createEntity(final String entityName, final CredentialManagerSubject subject,
            final CredentialManagerSubjectAltName subjectAltName,
            final CredentialManagerAlgorithm keyGenerationAlgorithm, final String entityProfileName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException {

        CredentialManagerEntity entity = null;

        entity = profileManager.createEntity(entityName, subject, subjectAltName, keyGenerationAlgorithm, entityProfileName);
        return entity;
    }

    @Override
    public CredentialManagerEntity getEntity(final String entityName) throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {

        CredentialManagerEntity endEntity = null;

        endEntity = profileManager.getEntity(CertificateUtils.getCN(entityName));

        return endEntity;
    }

    @Override
    public CredentialManagerProfileInfo getProfile(final String endEntityProfileName) throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        if (!credMPkiConfBean.isEnabled()) {
            throw new CredentialManagerInternalServiceException("Credential Manager Service not ready");
        }
        CredentialManagerProfileInfo profileInfo = null;
        profileInfo = profileManager.getProfile(endEntityProfileName);

        return profileInfo;
    }

    @Override
    public CredentialManagerX509Certificate[] getCertificate(final CredentialManagerPKCS10CertRequest csr, final String entityName,
            final boolean certificateChain, final String otp)
            throws CredentialManagerCertificateEncodingException, CredentialManagerEntityNotFoundException,
            CredentialManagerCertificateGenerationException, CredentialManagerInvalidCSRException, CredentialManagerInvalidEntityException,
            CredentialManagerCertificateExsitsException {
        CredentialManagerX509Certificate[] certificate = null;

        certificate = certificateManager.getCertificate(csr, CertificateUtils.getCN(entityName), certificateChain, otp);

        return certificate;
    }

    //
    // getTrustCertificate
    //

    @Override
    public CredentialManagerTrustMaps getTrustCertificates(final String profileName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {

        return innerGetTrustCertificates(profileName, ProfileType.ENTITY_PROFILE);

    }

    @Override
    public CredentialManagerTrustMaps getTrustCertificatesTP(final String trustProfileName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {

        return innerGetTrustCertificates(trustProfileName, ProfileType.TRUST_PROFILE);
    }

    /**
     * innerGetTrustCertificates
     *
     * @param profileName
     * @param profileType
     * @return
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerServiceException
     * @throws CredentialManagerProfileNotFoundException
     * @throws CredentialManagerCertificateEncodingException
     * @throws CredentialManagerInvalidProfileException
     */
    private CredentialManagerTrustMaps innerGetTrustCertificates(final String profileName, final ProfileType profileType)
            throws CredentialManagerInvalidArgumentException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException, CredentialManagerInternalServiceException {

        final CredentialManagerTrustMaps caMap = new CredentialManagerTrustMaps();
        CredentialManagerCALists trustCALists = new CredentialManagerCALists();

        switch (profileType) {
            case ENTITY_PROFILE:
                trustCALists = profileManager.getTrustCAList(profileName); // from entity profile
                break;
            case TRUST_PROFILE:
                trustCALists = profileManager.getTrustCAListFromTP(profileName, null); // from a single trust profile
                break;
            default: // being a private method it never goes here
                break;
        }

        if (trustCALists != null) {
            /**
             * Internal CAs
             */
            setTrustMap(trustCALists.getInternalCAList(), caMap.getInternalCATrustMap(), false);

            /**
             * External CAs
             */
            setTrustMap(trustCALists.getExternalCAList(), caMap.getExternalCATrustMap(), true);
        }

        return caMap;
    }

    //
    // compareTrustAndRetrieve
    //

    /*
     * (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmservice.api.CredMService# getTrustCertificates(java.lang.String, java.util.Set)
     */
    @Override
    public CredentialManagerTrustMaps compareTrustAndRetrieve(final String profileName,
            final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers,
            final boolean internalFlag, final boolean externalFlag)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {

        return innerCompareTrustAndRetrieve(profileName, ProfileType.ENTITY_PROFILE, currentTrustIdentifiers, internalFlag, externalFlag);
    }

    @Override
    public CredentialManagerTrustMaps compareTrustAndRetrieveTP(final String profileName,
            final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers,
            final boolean internalFlag, final boolean externalFlag)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {

        return innerCompareTrustAndRetrieve(profileName, ProfileType.TRUST_PROFILE, currentTrustIdentifiers, internalFlag, externalFlag);
    }

    /**
     * innerCompareTrustAndRetrieve
     *
     * @param profileName
     * @param profileType
     * @param currentTrustIdentifiers
     * @param internalFlag
     * @param externalFlag
     * @return
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerInternalServiceException
     * @throws CredentialManagerProfileNotFoundException
     * @throws CredentialManagerCertificateEncodingException
     * @throws CredentialManagerInvalidProfileException
     */
    private CredentialManagerTrustMaps innerCompareTrustAndRetrieve(final String profileName, final ProfileType profileType,
            final SortedSet<CredentialManagerCertificateIdentifier> currentTrustIdentifiers,
            final boolean internalFlag, final boolean externalFlag)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException {

        final CredentialManagerTrustMaps trustMap = innerGetTrustCertificates(profileName, profileType);

        if (trustMap == null || currentTrustIdentifiers == null) {
            throw new CredentialManagerInvalidArgumentException();
        }
        final SortedSet<CredentialManagerCertificateIdentifier> checkingTrustIdentifiers = extractTrustIdentifier(trustMap, internalFlag,
                externalFlag);
        final boolean result = checkingTrustIdentifiers.containsAll(currentTrustIdentifiers)
                && currentTrustIdentifiers.containsAll(checkingTrustIdentifiers);
        if (result) {
            // check is ok, return null to show there is null to update
            return null;
        }
        return trustMap;
    }

    /**
     * @param trust
     * @param internalFlag
     * @param externalFlag
     * @return
     */
    private SortedSet<CredentialManagerCertificateIdentifier> extractTrustIdentifier(final CredentialManagerTrustMaps trust,
            final boolean internalFlag, final boolean externalFlag) {
        final SortedSet<CredentialManagerCertificateIdentifier> ret = new TreeSet<CredentialManagerCertificateIdentifier>();
        if (internalFlag) {
            for (final CredentialManagerCertificateAuthority certAuth : trust.getInternalCATrustMap().values()) {
                for (final CredentialManagerX509Certificate credMCert : certAuth.getCACertificateChain()) {
                    final X509Certificate cert = credMCert.retrieveCertificate();
                    final CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(cert.getSubjectX500Principal(),
                            cert.getIssuerX500Principal(), cert.getSerialNumber());
                    ret.add(certId);
                }
            }
        }
        if (externalFlag) {
            for (final CredentialManagerCertificateAuthority certAuth : trust.getExternalCATrustMap().values()) {
                for (final CredentialManagerX509Certificate credMCert : certAuth.getCACertificateChain()) {
                    final X509Certificate cert = credMCert.retrieveCertificate();
                    final CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(cert.getSubjectX500Principal(),
                            cert.getIssuerX500Principal(), cert.getSerialNumber());
                    ret.add(certId);
                }
            }
        }
        return ret;
    }

    /**
     * @param clrs
     * @param internalFlag
     * @param externalFlag
     * @return
     */

    private SortedSet<CredentialManagerCRLIdentifier> extractClrIdentifier(final CredentialManagerCrlMaps clrs, final boolean internalFlag,
            final boolean externalFlag) {

        final SortedSet<CredentialManagerCRLIdentifier> ret = new TreeSet<CredentialManagerCRLIdentifier>();
        if (internalFlag && clrs.getInternalCACrlMap() != null) {
            for (final CredentialManagerX509CRL crl : clrs.getInternalCACrlMap().values()) {
                final X509CRL xclr = crl.retrieveCRL();
                ret.add(new CredentialManagerCRLIdentifier(xclr));
            }
        }

        if (externalFlag && clrs.getExternalCACrlMap() != null) {
            for (final CredentialManagerX509CRL crl : clrs.getExternalCACrlMap().values()) {
                final X509CRL xclr = crl.retrieveCRL();
                ret.add(new CredentialManagerCRLIdentifier(xclr));
            }

        }
        return ret;

    }

    /**
     * @param trustCAList
     * @param isExternal
     * @return
     * @throws CredentialManagerCertificateEncodingException
     */
    private void setTrustMap(final List<CredentialManagerTrustCA> trustCAList, final Map<String, CredentialManagerCertificateAuthority> cas,
            final boolean isExternal)
            throws CredentialManagerInvalidArgumentException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException, CredentialManagerInternalServiceException {
        for (final CredentialManagerTrustCA trustCA : trustCAList) {
            // this list comes from trustprofiles loop, so it could happen that the same trustCA
            // is added, but in one case doesnt require chain and in the other does (second check).
            if (cas.containsKey(trustCA.getTrustCAName()) && !trustCA.isChainRequired()) {
                continue;
            }
            final CredentialManagerCertificateAuthority certificates = new CredentialManagerCertificateAuthority(
                    certificateManagerPki.getTrustCertificates(trustCA, isExternal));

            for (final CredentialManagerCertificateAuthority casEntry : cas.values()) {
                for (final CredentialManagerX509Certificate casCert : casEntry.getCACertificateChain()) {
                    for (final Iterator<CredentialManagerX509Certificate> itCerts = certificates.getCACertificateChain().iterator(); itCerts
                            .hasNext();) {
                        final CredentialManagerX509Certificate entryCert = itCerts.next();
                        if (casCert.retrieveCertificate().getIssuerDN().equals(entryCert.retrieveCertificate().getIssuerDN())
                                && casCert.retrieveCertificate().getSerialNumber().equals(entryCert.retrieveCertificate().getSerialNumber())) {
                            certificates.getCACertificateChain().remove(entryCert);
                            break;
                        }
                    }
                }
            }
            if (!certificates.getCACertificateChain().isEmpty()) {
                cas.put(trustCA.getTrustCAName(), certificates);
            }
        }
    }

    //
    // getCRL
    //

    @Override
    public CredentialManagerCrlMaps getCRLs(final String endEntityProfileName, final boolean isChainRequired)
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLEncodingException {
        return innerGetCRLs(endEntityProfileName, ProfileType.ENTITY_PROFILE, isChainRequired);
    }

    @Override
    public CredentialManagerCrlMaps getCRLsTP(final String trustProfileName, final boolean isChainRequired)
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLEncodingException {
        return innerGetCRLs(trustProfileName, ProfileType.TRUST_PROFILE, isChainRequired);
    }

    /**
     * innerGetCRLs
     *
     * @param profileName
     * @param profileType
     * @param isChainRequired
     * @return
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerServiceException
     * @throws CredentialManagerProfileNotFoundException
     * @throws CredentialManagerInvalidProfileException
     * @throws CredentialManagerCertificateServiceException
     * @throws CredentialManagerCRLServiceException
     * @throws CredentialManagerCRLEncodingException
     */
    private CredentialManagerCrlMaps innerGetCRLs(final String profileName, final ProfileType profileType, final boolean isChainRequired)
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLEncodingException {

        final CredentialManagerCrlMaps crls = new CredentialManagerCrlMaps();
        CredentialManagerCALists trustCALists = new CredentialManagerCALists();
        switch (profileType) {
            case ENTITY_PROFILE:
                trustCALists = profileManager.getTrustCAList(profileName); // form entity profile
                break;
            case TRUST_PROFILE:
                trustCALists = profileManager.getTrustCAListFromTP(profileName, null); // form a single trust profile
                break;
            default:
                trustCALists = null;
                log.info("getCRLs called from invalid profile " + profileName);
                break;
        }
        if (trustCALists != null) {
            setCrlMap(trustCALists.getInternalCAList(), crls.getInternalCACrlMap(), isChainRequired, false);
            setCrlMap(trustCALists.getExternalCAList(), crls.getExternalCACrlMap(), isChainRequired, true);
        }
        return crls;
    }

    //
    // compareCrlsAndRetrieve
    //

    /*
     * (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmservice.api.CredMService# compareCrlsAndRetrieve(java.lang.String, boolean)
     */
    @Override
    public CredentialManagerCrlMaps compareCrlsAndRetrieve(final String entityProfileName, final boolean isChainRequired,
            final SortedSet<CredentialManagerCRLIdentifier> currentClrIdentifiers,
            final boolean internalFlag, final boolean externalFlag)
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLEncodingException

    {
        return innerCompareCrlsAndRetrieve(entityProfileName, ProfileType.ENTITY_PROFILE, isChainRequired, currentClrIdentifiers, internalFlag,
                externalFlag);
    }

    @Override
    public CredentialManagerCrlMaps compareCrlsAndRetrieveTP(final String trustProfileName, final boolean isChainRequired,
            final SortedSet<CredentialManagerCRLIdentifier> currentClrIdentifiers,
            final boolean internalFlag, final boolean externalFlag)
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLEncodingException

    {
        return innerCompareCrlsAndRetrieve(trustProfileName, ProfileType.TRUST_PROFILE, isChainRequired, currentClrIdentifiers, internalFlag,
                externalFlag);
    }

    /**
     * innerCompareCrlsAndRetrieve
     *
     * @param profileName
     * @param profileType
     * @param isChainRequired
     * @param currentClrIdentifiers
     * @param internalFlag
     * @param externalFlag
     * @return
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerServiceException
     * @throws CredentialManagerProfileNotFoundException
     * @throws CredentialManagerInvalidProfileException
     * @throws CredentialManagerCertificateServiceException
     * @throws CredentialManagerCRLServiceException
     * @throws CredentialManagerCRLEncodingException
     */
    private CredentialManagerCrlMaps innerCompareCrlsAndRetrieve(final String profileName, final ProfileType profileType,
            final boolean isChainRequired,
            final SortedSet<CredentialManagerCRLIdentifier> currentClrIdentifiers,
            final boolean internalFlag, final boolean externalFlag)
            throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLEncodingException

    {

        final CredentialManagerCrlMaps clrMap = innerGetCRLs(profileName, profileType, isChainRequired);

        if (clrMap == null || currentClrIdentifiers == null) {
            throw new CredentialManagerInvalidArgumentException();
        }

        final SortedSet<CredentialManagerCRLIdentifier> checkingCrlIdentifiers = extractClrIdentifier(clrMap, internalFlag, externalFlag);

        boolean result = false;
        if (currentClrIdentifiers.size() == checkingCrlIdentifiers.size()) {
            final int dim = currentClrIdentifiers.size();
            int found = 0;
            for (final CredentialManagerCRLIdentifier crlId : currentClrIdentifiers) {
                for (final CredentialManagerCRLIdentifier PKIcrlId : checkingCrlIdentifiers) {
                    if (PKIcrlId.equals(crlId)) {
                        found++;
                        break;
                    }
                }
            }
            if (found == dim) {
                result = true;
            }
        }

        if (result) {
            // check is ok, return null to show there is null to update
            log.info("CRL check found no difference for  " + profileName);
            return null;
        }
        log.info("CRL check NEW CRLs on PKI for " + profileName);
        return clrMap;
    }

    /**
     * getEntitiesByCategory
     *
     * @param categoryName
     * @return set of CredentialManagerEntity (if there are no entities for this category an empty set is returned)
     * @throws CredentialManagerInvalidArgumentException
     *             if the category doesn't exist
     * @throws CredentialManagerInternalServiceException
     *             for any other reason
     */
    @Override
    public Set<CredentialManagerEntity> getEntitiesByCategory(final String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {

        Set<CredentialManagerEntity> entitySet = new HashSet<CredentialManagerEntity>();
        entitySet = profileManager.getEntitiesByCategory(categoryName);
        // throws CredentialManagerInvalidArgumentException if the category not exists
        // throws CredentialManagerInternalServiceException for internal error
        return entitySet;
    }

    /**
     * getEntitiesSummaryByCategory
     *
     * @param categoryName
     * @return set of CredentialManagerEntity (if there are no entities for this category an empty set is returned)
     * @throws CredentialManagerInvalidArgumentException
     *             if the category doesn't exist
     * @throws CredentialManagerInternalServiceException
     *             for any other reason
     */
    @Override
    public Set<CredentialManagerEntity> getEntitiesSummaryByCategory(final String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {

        Set<CredentialManagerEntity> entitySet = new HashSet<CredentialManagerEntity>();
        entitySet = profileManager.getEntitiesSummaryByCategory(categoryName);
        return entitySet;
    }

    /**
     *
     */
    @Override
    public boolean isOTPValid(final String entityName, final String otp)
            throws CredentialManagerEntityNotFoundException, CredentialManagerOtpExpiredException, CredentialManagerInternalServiceException {

        return profileManager.isOTPValid(entityName, otp);
    }

    /**
     * setCrlMap
     *
     * @param trustCAList
     * @param caCrl
     * @param isChainRequired
     * @param isExternal
     * @throws CredentialManagerCRLEncodingException
     */
    private void setCrlMap(final List<CredentialManagerTrustCA> trustCAList, final Map<String, CredentialManagerX509CRL> caCrl,
            final boolean isChainRequired, final boolean isExternal)
            throws CredentialManagerCRLServiceException, CredentialManagerCertificateServiceException, CredentialManagerCRLEncodingException {

        for (final CredentialManagerTrustCA trustCA : trustCAList) {
            if (caCrl.containsKey(trustCA.getTrustCAName())) {
                continue;
            }
            try {
                final Map<String, CredentialManagerX509CRL> crls = certificateManager.getCrl(trustCA.getTrustCAName(), trustCA.isChainRequired(),
                        isExternal);
                caCrl.putAll(crls);
            } catch (final CredentialManagerCRLServiceException e) {
                log.error("CRL Service Error during retrieving for " + trustCA);
                log.debug("getCrl exception {}", e);
                throw new CredentialManagerCRLServiceException();
            } catch (final CredentialManagerCertificateServiceException e) {
                log.warn("PKI non defined ..." + trustCA);
                log.debug("getCrl exception {}", e);
                throw new CredentialManagerCRLServiceException();
            }

        }
    }

    /**
     * revokeCertificateByEntity
     *
     * @param entityName
     * @param reason
     * @param invalidityDate
     * @throw CredentialManagerServiceException
     * @throw CredentialManagerEntityNotFoundException
     */
    @Override
    public void revokeCertificateByEntity(final String entityName, final CredentialManagerRevocationReason reason, final Date invalidityDate)
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException {

        certificateManager.RevokeCertificateByEntity(entityName, reason, invalidityDate);

    }

    /**
     * revokeCertificateById
     *
     * @param certificateIdentifier
     * @param reason
     * @param invalidityDate
     * @throw CredentialManagerServiceException
     * @throw CredentialManagerCertificateNotFoundException
     * @throw CredentialManagerExpiredCertificateException
     * @throw CredentialManagerAlreadyRevokedCertificateException
     */
    @Override
    public void revokeCertificateById(final CredentialManagerCertificateIdentifier certificateIdentifer,
            final CredentialManagerRevocationReason reason, final Date invalidityDate)
            throws CredentialManagerInternalServiceException, CredentialManagerCertificateNotFoundException,
            CredentialManagerExpiredCertificateException, CredentialManagerAlreadyRevokedCertificateException {
        try {
            certificateManager.RevokeCertificateById(certificateIdentifer, reason, invalidityDate);
        } catch (final CredentialManagerCertificateServiceException e) {
            log.debug("RevokeCertificateById exception {}", e);
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final CredentialManagerCertificateNotFoundException | CredentialManagerExpiredCertificateException
                | CredentialManagerAlreadyRevokedCertificateException e) {
            throw e;
        }
    }

    /**
     * listCertificates
     *
     * @param entityName
     * @param entityType
     * @param certsStatus
     * @throw CredentialManagerInternalServiceException
     */
    @Override
    public List<CredentialManagerX509Certificate> listCertificates(final String entityName, final CredentialManagerEntityType entityType,
            final CredentialManagerCertificateStatus... certsStatus)
            throws CredentialManagerInternalServiceException {
        List<CredentialManagerX509Certificate> credMCertList = new ArrayList<CredentialManagerX509Certificate>();
        try {
            credMCertList = certificateManager.ListCertificates(entityName, entityType, certsStatus);
        } catch (CredentialManagerCertificateServiceException | CredentialManagerEntityNotFoundException | CredentialManagerInvalidArgumentException
                | CredentialManagerCertificateEncodingException e) {
            log.debug("ListCertificates Exception {}", e);
            throw new CredentialManagerInternalServiceException();
        } catch (final CredentialManagerCertificateNotFoundException e) {
            log.info("Certificate/s not found for entity " + entityName + " given certificate status/es: " + Arrays.toString(certsStatus));
            log.debug("ListCertificates Exception {}", e);
        }
        return credMCertList;
    }

    /*
     * (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmservice.api.CredMService#getVersion()
     */
    @Override
    public String getVersion() {
        CMSERVICE_VERSION = PropertiesReader.getProperties(FILE_PROPERTIES).getProperty(VERSION_PROPERTIES);
        return CMSERVICE_VERSION;
    }

    @Override
    public void printCommandOnRecorder(final String message, final CommandPhase category, final String source, final String entityName,
            final String infos)
            throws IllegalArgumentException {
        if (message == null || source == null || entityName == null) {
            throw new IllegalArgumentException("CredMService printOnRecorder: invalid argument exception");
        }
        certificateManager.printCommandOnRecorder(message, category, source, entityName, infos);
    }

    @Override
    public void printErrorOnRecorder(final String message, final ErrorSeverity category, final String source, final String entityName,
            final String infos)
            throws IllegalArgumentException {
        if (message == null || source == null || entityName == null) {
            throw new IllegalArgumentException("CredMService printOnRecorder: invalid argument exception");
        }
        certificateManager.printErrorOnRecorder(message, category, source, entityName, infos);
    }

    /*
     * (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmservice.api.CredMService#getPibParameters(java.util.List)
     */
    @Override
    public CredentialManagerPIBParameters getPibParameters() {

        return credentialManagerConfigurationListener.getPibServiceParams();
    }

    /**
     * listCertificatesSummary
     *
     * @param entityName
     * @param entityType
     * @param credMCertStatus
     * @throw CredentialManagerInternalServiceException
     * @throw CredentialManagerCertificateNotFoundException
     * @throw CredentialManagerEntityNotFoundException
     */
    @Override
    public List<CredentialManagerX500CertificateSummary> listCertificatesSummary(final String entityName,
            final CredentialManagerEntityType entityType,
            final CredentialManagerCertificateStatus... credMCertStatus)
            throws CredentialManagerCertificateNotFoundException, CredentialManagerEntityNotFoundException,
            CredentialManagerInternalServiceException {

        List<CredentialManagerX500CertificateSummary> credMCertsSummaryList = new ArrayList<CredentialManagerX500CertificateSummary>();

        try {
            credMCertsSummaryList = certificateManager.listCertificatesSummary(entityName, entityType, credMCertStatus);
        } catch (CredentialManagerCertificateServiceException | CredentialManagerInvalidArgumentException
                | CredentialManagerCertificateEncodingException e) {
            log.debug("listCertificatesSummary Exception {}", e);
            throw new CredentialManagerInternalServiceException();
        }

        return credMCertsSummaryList;
    }

}
