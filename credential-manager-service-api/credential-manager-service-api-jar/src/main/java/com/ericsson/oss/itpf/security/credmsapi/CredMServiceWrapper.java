/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ConfigurationException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustSource;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PropertiesReader;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
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
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidOtpException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerOtpExpiredException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLIdentifier;
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
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

public class CredMServiceWrapper {

    private static final Logger LOG = LogManager.getLogger(CredMServiceWrapper.class);

    // MODE CONSTANTS
    public static enum channelMode {
        SECURE_CHANNEL, REST_CHANNEL, REST_CHANNEL_TEST
    };

    channelMode mode = channelMode.SECURE_CHANNEL;
    CredMService credMService = null;
    CredentialManagerServiceRestClient restClient = null;

    // used only for test
    public CredMServiceWrapper(final CredMService credMServ, final CredentialManagerServiceRestClient credentialManagerServiceRestClient) {
        this.credMService = credMServ;
        this.restClient = credentialManagerServiceRestClient;
    }

    /**
     * CredMServiceWrapper
     */
    public CredMServiceWrapper() {
    }

    /**
     * getMode
     * 
     * @return
     */
    public channelMode getMode() {
        return this.mode;
    }

    /**
     * CredMServiceWrapper
     * 
     * @param mode
     * @throws IssueCertificateException
     */
    public CredMServiceWrapper(final channelMode mode, final boolean noLoop) throws IssueCertificateException {

        this.mode = mode;
        switch (this.mode) {

        case SECURE_CHANNEL:
            /**
             * Get remote object
             */
            try {
                this.credMService = new JNDIResolver().resolveCredMService();
            } catch (final IllegalStateException e) {
                throw (new IssueCertificateException(e.getMessage()));
            }
            break;

        case REST_CHANNEL:
            // note that this call could loop forever if not REST services
            // available
            this.openAndTryRestChannel(noLoop); // false
            break;

        case REST_CHANNEL_TEST:
            // it exits also if not find a REST channel (used only for test)
            this.openAndTryRestChannel(noLoop); // true
            break;
        }

    }

    /**
     * openAndTryRestChannel
     * 
     * @throws IssueCertificateException
     */
    private void openAndTryRestChannel(final boolean noLoop) throws IssueCertificateException {
        /**
         * Read hostname and port from config file
         */
        String[] addresses;
        try {
            addresses = PropertiesReader.getProperty(PropertiesReader.ADDRESS, "").split(PropertiesReader.ADDRESS_SEPARATOR);
        } catch (final ConfigurationException e2) {
            LOG.error(ErrorMsg.API_ERROR_SERVICE_PARSE_RESTADDRESSES);
            // e2.printStackTrace();
            throw new IssueCertificateException();
        }

        // infinite loop unless a REST service is found
        boolean openRest = noLoop;
        boolean hostFound = false;
        do {
            for (final String addr : addresses) {
                try {
                    this.restClient = new CredentialManagerServiceRestClient(addr);

                    // use the getProfile to test if the REST service is
                    // available
                    this.restClient.getProfile();
                } catch (final Exception e) {
                    LOG.info("Test REST channel : " + e);
                    continue;
                }
                System.out.println("Connected to " + addr);
                LOG.info("Connected to " + addr);
                hostFound = true;
                openRest = true;
                break;
            }
            if (!hostFound && !openRest) { // useless waiting 5 secs if openRest
                                           // is true (= noLoop true)
                try {
                    System.out.println("Connection failed: retry... ");
                    Thread.sleep(5000);
                } catch (final InterruptedException e) {
                    LOG.error(ErrorMsg.API_ERROR_SERVICE_SLEEP);
                }
            }
        } while (!openRest);

        if (hostFound == false) {
            System.out.println("SPS HOST NOT FOUND, exiting application!");
            LOG.info("SPS HOST NOT FOUND!");
            throw new IssueCertificateException();
        }
    } // end of openAndTryRestChannel

    /**
     * createAndGetEndEntity
     * 
     * (only for REST channel)
     * 
     * @param entityName
     * @param reqPassword
     * @return
     * @throws IssueCertificateException
     */
    public CredentialManagerEntity createAndGetEndEntity(final String entityName, final String reqPassword) throws IssueCertificateException {

        CredentialManagerEntity result = null;

        switch (this.mode) {
        case SECURE_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_SECURE_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        case REST_CHANNEL:
            if (this.restClient != null) {
                result = this.restClient.createAndGetEndEntity(entityName, reqPassword);
            }
            break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        }
        return result;
    }

    /**
     * createAndGetEntity
     * 
     * (only for SECURE CHANNEL)
     * 
     * @param entityName
     * @param subject
     * @param subjectAltName
     * @param keyGenerationAlgorithm
     * @param entityProfileName
     * @return
     * @throws IssueCertificateException
     */
    public CredentialManagerEntity createAndGetEntity(final String entityName, final CredentialManagerSubject subject, final CredentialManagerSubjectAltName subjectAltName,
            final CredentialManagerAlgorithm keyGenerationAlgorithm, final String entityProfileName) throws IssueCertificateException {

        CredentialManagerEntity result = null;

        switch (this.mode) {
        case SECURE_CHANNEL: {
            if (this.credMService != null) {
                try {
                    result = this.credMService.createAndGetEntity(entityName, subject, subjectAltName, keyGenerationAlgorithm, entityProfileName);
                } catch (CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException | CredentialManagerInvalidEntityException | CredentialManagerProfileNotFoundException e) { //NOSONAR 
                    // throw new IssueCertificateException(e.getMessage());
                    LOG.debug("createAndGetEntity exception : " + e.getMessage()); 
                }
            }
        }
            break;
        case REST_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        }
        return result;
    }

    /**
     * getEntity
     * 
     * @param entityName
     * @return
     */
    public CredentialManagerEntity getEntity(final String entityName) {

        // TODO check if the call from ENIS is correct

        CredentialManagerEntity result = null;
        if (this.credMService != null) {
            try {
                result = this.credMService.getEntity(entityName);
            } catch (CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException | CredentialManagerEntityNotFoundException | CredentialManagerInvalidEntityException e) {
                LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_ENTITY, entityName);
            }
        }
        return result;
    }

    /**
     * getEntity
     * 
     * @param entityName
     * @return
     */
    public CredentialManagerEntity getExistingEntity(final String entityName) throws CredentialManagerEntityNotFoundException {

        // TODO check if the call from ENIS is correct

        CredentialManagerEntity result = null;
        if (this.credMService != null) {
            try {
                result = this.credMService.getEntity(entityName);
            } catch (CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException | CredentialManagerInvalidEntityException e) {
                LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_ENTITY, entityName);
            }
        }
        return result;
    }

    /**
     * getProfile
     * 
     * @param entityProfileName
     * @return
     */
    public CredentialManagerProfileInfo getProfile() {
        return this.getProfile("");
    }

    public CredentialManagerProfileInfo getProfile(final String entityProfileName) {

        CredentialManagerProfileInfo result = null;

        switch (this.mode) {
        case SECURE_CHANNEL:
            for (int i = 0; i < 5; i++) {
                if (this.credMService != null) {
                    try {
                        result = this.credMService.getProfile(entityProfileName);
                    } catch (final CredentialManagerInternalServiceException e) {
                        LOG.error(ErrorMsg.API_ERROR_SERVICE_SECURE_INVALID_METHOD + " or SPS MISSING");
                        this.credMService = new JNDIResolver().resolveCredMService();
                        continue;
                    } catch (CredentialManagerInvalidArgumentException | CredentialManagerProfileNotFoundException | CredentialManagerInvalidProfileException e) {
                        LOG.error(ErrorMsg.API_ERROR_SERVICE_SECURE_INVALID_METHOD);
                    }
                }
                break;
            }
            break;
        case REST_CHANNEL:
            if (this.restClient != null) {
                try {
                    result = this.restClient.getProfile();
                } catch (final Exception e) {
                    LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
                }
            }
            break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            // throw (new IssueCertificateException("Invalid method calling"));
            break;
        }
        return result;
    }

    /**
     * getCertificate
     * 
     * parameters semplificated for REST channel
     * 
     * @param csr
     * @return
     * @throws IssueCertificateException
     */
    public CredentialManagerX509Certificate[] getCertificate(final PKCS10CertificationRequest csr) throws IssueCertificateException {

        CredentialManagerX509Certificate[] result = null;

        switch (this.mode) {
        case SECURE_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;

        case REST_CHANNEL:
            if (this.restClient != null) {
                result = this.restClient.getCertificate(csr);
            }
            break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        }
        return result;
    }

    /**
     * getCertificate
     * 
     * @param csr
     * @param entityName
     * @param issuer
     * @param validity
     * @return
     * @throws IssueCertificateException
     */
    public CredentialManagerX509Certificate[] getCertificate(final CredentialManagerPKCS10CertRequest csr, final String entityName, final boolean certificateChain, final String otp)
            throws IssueCertificateException, OtpExpiredException, OtpNotValidException {

        CredentialManagerX509Certificate[] result = null;

        switch (this.mode) {
        case SECURE_CHANNEL:
            if (this.credMService != null) {
                try {
                    result = this.credMService.getCertificate(csr, entityName, certificateChain, otp);

                } catch (CredentialManagerCertificateEncodingException | CredentialManagerEntityNotFoundException | CredentialManagerCertificateGenerationException
                        | CredentialManagerInvalidCSRException | CredentialManagerInvalidEntityException | CredentialManagerCertificateExsitsException e) {
                    LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_CERTIFICATE, entityName);
                    throw (new IssueCertificateException("Getting from Service error"));
                } catch (CredentialManagerOtpExpiredException e) {
                    LOG.error(ErrorMsg.API_ERROR_SERVICE_EXPIRED_OTP, entityName);
                    throw (new OtpExpiredException("Getting from Service error"));
                } catch (CredentialManagerInvalidOtpException e) {
                    LOG.error(ErrorMsg.API_ERROR_SERVICE_INVALID_OTP, entityName);
                    throw (new OtpNotValidException("Getting from Service error"));
                }
            }
            break;

        case REST_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        }
        return result;
    }

    /**
     * getCertificateChain
     * 
     * @param csr
     * @param entityName
     * @return
     * @throws IssueCertificateException
     */
    /*
     * This method is NOT USED at the moment (maybe it should be removed)!
     */
    // public CredentialManagerX509Certificate[] getCertificateChain(final
    // CredentialManagerPKCS10CertRequest csr, final String entityName, final
    // boolean certificateChain)
    // throws IssueCertificateException {
    //
    // CredentialManagerX509Certificate[] result = null;
    //
    // switch (this.mode) {
    // case SECURE_CHANNEL:
    // if (this.credMService != null) {
    // try {
    // // TODO
    // // FOR NOW WE ALWAYS CALL THE SINGLE CERTIFICATE API AND BUILD A DUMMY
    // CHAIN
    //
    // result = this.credMService.getCertificate(csr, entityName,
    // certificateChain);
    //
    // } catch (CredentialManagerCertificateEncodingException |
    // CredentialManagerEntityNotFoundException |
    // CredentialManagerCertificateGenerationException
    // | CredentialManagerInvalidCSRException |
    // CredentialManagerInvalidEntityException |
    // CredentialManagerCertificateExsitsException e) {
    // LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_CERTIFICATE, entityName);
    // //throw new IssueCertificateException(e.getMessage());
    // }
    // }
    // break;
    //
    // case REST_CHANNEL:
    // LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
    // throw (new IssueCertificateException("Invalid method calling"));
    // // break;
    // default:
    // LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
    // throw (new IssueCertificateException("Invalid method calling"));
    // //break;
    // }
    // return result;
    // }

    /**
     * getTrustCertificates
     * 
     * @param entityProfileName
     * @param profileType
     * @return
     */
    public CredentialManagerTrustMaps getTrustCertificates() {
        return this.getTrustCertificates("", CredentialManagerProfileType.ENTITY_PROFILE);
    }

    /**
     * getTrustCertificates
     * 
     * @param profileName
     * @param profileType
     * @return
     */
    public CredentialManagerTrustMaps getTrustCertificates(final String profileName, final CredentialManagerProfileType profileType) {

        CredentialManagerTrustMaps resultMap = new CredentialManagerTrustMaps();
        // System.out.println(" mode is " + this.mode);

        switch (this.mode) {
        case SECURE_CHANNEL:
            if (this.credMService != null) {
                try {
                    switch (profileType) {
                    case ENTITY_PROFILE:
                        resultMap = this.credMService.getTrustCertificates(profileName);
                        break;
                    case TRUST_PROFILE:
                        resultMap = this.credMService.getTrustCertificatesTP(profileName);
                        break;
                    default:
                        LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_TRUSTCERTS, profileType, " wrong profile type");
                    }
                } catch (CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException | CredentialManagerProfileNotFoundException | CredentialManagerCertificateEncodingException | CredentialManagerInvalidProfileException e) { //NOSONAR
                    LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_TRUSTCERTS, profileName, e.getMessage());
                }
            }
            break;

        case REST_CHANNEL:
            if (this.restClient != null) {
                resultMap = this.restClient.getTrust();
            }
            break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            // throw (new IssueCertificateException("Invalid method calling"));
            break;
        }
        return resultMap;

    } // end of getTrustCertificates

    /**
     * getCRLs
     * 
     * @param profileName
     * @param profileType
     * @return
     * @throws IssueCertificateException
     */
    public CredentialManagerCrlMaps getCRLs(final String profileName, final CredentialManagerProfileType profileType) throws IssueCertificateException {

        CredentialManagerCrlMaps result = null;

        // System.out.println(" mode is " + this.mode);

        switch (this.mode) {
        case SECURE_CHANNEL:
            if (this.credMService != null) {
                try {

                    // TODO: isChainRequired is not yet supported
                    final boolean isChainRequired = false;
                    switch (profileType) {
                    case ENTITY_PROFILE:
                        result = this.credMService.getCRLs(profileName, isChainRequired);
                        break;
                    case TRUST_PROFILE:
                        result = this.credMService.getCRLsTP(profileName, isChainRequired);
                        break;
                    default:
                        LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_TRUSTCERTS, profileType, " wrong profile type");
                    }

                } catch (CredentialManagerInvalidArgumentException | CredentialManagerProfileNotFoundException | CredentialManagerInvalidProfileException
                        | CredentialManagerCertificateServiceException | CredentialManagerCRLServiceException | CredentialManagerCRLEncodingException e) {
                    LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_CRL, profileName);
                    throw (new IssueCertificateException("CredMService failure in getCRLs method"));
                }
            }
            break;

        case REST_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new IssueCertificateException("Invalid method calling"));
            // break;
        }
        return result;

    } // end of getCRLs

    /**
     * compareCRLsAndRetrieve
     * 
     * @param profileName
     * @param profileType
     * @param currentCrl
     * @param source
     * @return
     */
    public CredentialManagerCrlMaps compareCRLsAndRetrieve(final String profileName, final CredentialManagerProfileType profileType, final SortedSet<CredentialManagerCRLIdentifier> currentCrl,
            final TrustSource source) {

        CredentialManagerCrlMaps retrievedCrl = null;
        boolean internalFlag = false;
        boolean externalFlag = false;
        // remove from the map the trusts not present in the trustStore
        switch (source) {
        case INTERNAL:
            internalFlag = true;
            break;
        case EXTERNAL:
            externalFlag = true;
            break;
        case BOTH:
            internalFlag = true;
            externalFlag = true;
            break;
        }

        // check the channel
        switch (this.mode) {
        case SECURE_CHANNEL:
            if (this.credMService != null) {
                try {
                    switch (profileType) {
                    case ENTITY_PROFILE:
                        retrievedCrl = this.credMService.compareCrlsAndRetrieve(profileName, false, currentCrl, internalFlag, externalFlag);
                        break;
                    case TRUST_PROFILE:
                        retrievedCrl = this.credMService.compareCrlsAndRetrieveTP(profileName, false, currentCrl, internalFlag, externalFlag);
                        break;
                    default:
                        LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_TRUSTCERTS, profileType, "wrong profile type");
                    }
                } catch (CredentialManagerInvalidArgumentException | CredentialManagerProfileNotFoundException | CredentialManagerInvalidProfileException | CredentialManagerCertificateServiceException | CredentialManagerCRLServiceException | CredentialManagerCRLEncodingException e) { //NOSONAR 
                    LOG.error("compareCrlsAndRetrieve exception : " + e.getMessage());
                    // throw (new CredentialManagerInternalServiceException(e));
                }
            }
            break;

        case REST_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            return null;
            // break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            // throw (new IssueCertificateException("Invalid method calling"));
            break;
        }
        return retrievedCrl;

    } // end of compareCRLsAndRetrieve

    /**
     * checkCurrentTrust
     * 
     * @param retrievedTrust
     * @param currentTrust
     * @param source
     * @return
     */
    public CredentialManagerTrustMaps checkCurrentTrust(final String profileName, final CredentialManagerProfileType profileType, final SortedSet<CredentialManagerCertificateIdentifier> currentTrust,
            final TrustSource source) {

        CredentialManagerTrustMaps retrievedTrust = null;
        boolean internalFlag = false;
        boolean externalFlag = false;
        // remove from the map the trusts not present in the trustStore
        switch (source) {
        case INTERNAL:
            internalFlag = true;
            break;
        case EXTERNAL:
            externalFlag = true;
            break;
        case BOTH:
            internalFlag = true;
            externalFlag = true;
            break;
        }

        // check the channel
        switch (this.mode) {
        case SECURE_CHANNEL:

            if (this.credMService != null) {
                try {
                    switch (profileType) {
                    case ENTITY_PROFILE:
                        retrievedTrust = this.credMService.compareTrustAndRetrieve(profileName, currentTrust, internalFlag, externalFlag);
                        break;
                    case TRUST_PROFILE:
                        retrievedTrust = this.credMService.compareTrustAndRetrieveTP(profileName, currentTrust, internalFlag, externalFlag);
                        break;
                    default:
                        LOG.error("checkCurrentTrust invalid type : " + profileType);
                    }
                } catch (CredentialManagerInvalidArgumentException | CredentialManagerCertificateEncodingException | CredentialManagerInternalServiceException e) { //NOSONAR 
                    LOG.error("checkCurrentTrust exception : " + e.getMessage());
                    // throw (new CredentialManagerInternalServiceException(e));
                }
            }
            break;

        case REST_CHANNEL:
            if (this.restClient != null) {
                retrievedTrust = this.restClient.getTrust(); //TODO Workaround: it will be updated with new REST Api from CredM Service to compare trusts first
            }
            break;

        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            // throw (new IssueCertificateException("Invalid method calling"));
            break;
        }
        return retrievedTrust;

    } // end of checkCurrentTrust

    // void revokeCertificateById(final CredentialManagerCertificateIdentifier
    // certificateIdentifer,
    // final CredentialManagerRevocationReason reason, final Date
    // invalidityDate)
    // throws CredentialManagerInternalServiceException,
    // CredentialManagerCertificateNotFoundException;

    /**
     * revokeCertificateById
     * 
     * @param certificateIdentifer
     * @param invalidityDaten
     * @return
     */
    public Boolean revokeCertificateById(final CredentialManagerCertificateIdentifier certificateIdentifer) {

        Boolean result = null;

        try {
            result = this.revokeCertificateById(certificateIdentifer, CredentialManagerRevocationReason.SUPERSEDED, Calendar.getInstance().getTime());
        } catch (final CredentialManagerInternalServiceException | CredentialManagerExpiredCertificateException | CredentialManagerAlreadyRevokedCertificateException e) {
            result = false;
        } catch (final CredentialManagerCertificateNotFoundException e) {
            result = true;
        }

        return result;
    }

    public Boolean revokeCertificateById(final CredentialManagerCertificateIdentifier certificateIdentifer, final CredentialManagerRevocationReason reason, final Date invalidityDate)
            throws CredentialManagerInternalServiceException, CredentialManagerCertificateNotFoundException, CredentialManagerExpiredCertificateException,
            CredentialManagerAlreadyRevokedCertificateException {

        Boolean result = null;

        switch (this.mode) {
        case SECURE_CHANNEL:
            if (this.credMService != null) {

                try {
                    this.credMService.revokeCertificateById(certificateIdentifer, reason, invalidityDate);
                } catch (final CredentialManagerInternalServiceException e) {
                    LOG.error("revokeCertificateById : CredentialManagerInternalServiceException");
                    throw (new CredentialManagerInternalServiceException(e));
                } catch (final CredentialManagerCertificateNotFoundException e) {
                    LOG.error("revokeCertificateById : certificate not found");
                    throw (new CredentialManagerCertificateNotFoundException(e));
                } catch (final CredentialManagerExpiredCertificateException e) {
                    LOG.error("revokeCertificateById : certificate expired");
                    throw (new CredentialManagerExpiredCertificateException(e));
                } catch (final CredentialManagerAlreadyRevokedCertificateException e) {
                    LOG.error("revokeCertificateById : certificate already revoked");
                    throw (new CredentialManagerAlreadyRevokedCertificateException(e));
                }
                result = true;
            }
            break;

        case REST_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            // throw (new IssueCertificateException("Invalid method calling"));
            break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            // throw (new IssueCertificateException("Invalid method calling"));
            break;
        }
        return result;
    }

    /**
     * listActiveCertificates
     * 
     * @param entityName
     * @return
     */
    public List<CredentialManagerX509Certificate> listActiveCertificates(final String entityName) {

        List<CredentialManagerX509Certificate> result = null;

        switch (this.mode) {
        case SECURE_CHANNEL:
            if (this.credMService != null) {

                try {
                    result = this.credMService.listCertificates(entityName, CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
                } catch (final CredentialManagerInternalServiceException e) {
                    LOG.error("CredentialManagerInternalServiceException: listCertificates for " + entityName);
                }
            }
            break;

        case REST_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            // throw (new IssueCertificateException("Invalid method calling"));
            break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            // throw (new IssueCertificateException("Invalid method calling"));
            break;
        }
        return result;
    }

    /**
     * getEntitiesByCategory
     * 
     * @param categoryName
     * @return
     */
    public Set<CredentialManagerEntity> getEntitiesByCategory(final String categoryName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {

        Set<CredentialManagerEntity> result = null;
        if (this.credMService != null) {
            result = this.credMService.getEntitiesByCategory(categoryName);
        }
        return result;
    }

    
    /**
     * getEntitiesSummaryByCategory
     * 
     * @param categoryName
     * @return
     */
    public Set<CredentialManagerEntity> getEntitiesSummaryByCategory(final String categoryName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {

        Set<CredentialManagerEntity> result = null;
        if (this.credMService != null) {
            result = this.credMService.getEntitiesSummaryByCategory(categoryName);
        }
        return result;
    }

    public boolean isOTPValid(String entityName, String otp) throws CredentialManagerEntityNotFoundException, CredentialManagerOtpExpiredException, CredentialManagerInternalServiceException {

        if (this.credMService != null) {
            return this.credMService.isOTPValid(entityName, otp);
        }

        return false;
    }

    /**
     * revokeCertificateByEntity
     * 
     * (only for SECURE CHANNEL)
     * 
     * @param entityName
     * @param reason
     * @param date
     * @throws RevokeCertificateException
     * @throws EntityNotFoundException
     */
    public void revokeCertificateByEntity(final String entityName, final CredentialManagerRevocationReason reason, final Date date) throws RevokeCertificateException, EntityNotFoundException {

        switch (this.mode) {
        case SECURE_CHANNEL: {
            if (this.credMService != null) {
                try {
                    this.credMService.revokeCertificateByEntity(entityName, reason, date);
                } catch (final CredentialManagerInternalServiceException e) {
                    LOG.error("CredMService Internal Error");
                    throw new RevokeCertificateException(e.getMessage());
                } catch (final CredentialManagerEntityNotFoundException e) {
                    LOG.error("CredMService Entity Not Found");
                    throw new EntityNotFoundException(e.getMessage());
                }
            }
        }
            break;
        case REST_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new RevokeCertificateException("Invalid method calling"));
            // break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new RevokeCertificateException("Invalid method calling"));
            // break;
        }
    }

    /**
     * Print Command on System Recorder (Credential Manager Service)
     * 
     * @param message
     * @param category
     * @param source
     * @param entityName
     * @param infos
     */

    public void printCommandOnSystemRecorder(final String message, final CommandPhase category, final String source, final String entityName, String infos) {
        if (infos == null) {
            infos = "";
        }
        String hostname = null;
        try {
            InetAddress host = InetAddress.getLocalHost();
            hostname = host.getHostName();
        } catch (UnknownHostException e1) {
            hostname = "";
        }
        System.out.println("SYSTEM RECORDER COMMAND = { (s):" + source + "-(m):" + message + "-(e):" + entityName + "-(i):" + hostname + "| " + infos + " }");
        if (this.credMService != null) {
            try {
                this.credMService.printCommandOnRecorder(message, category, source, entityName, hostname + " - " + infos);
            } catch (final IllegalArgumentException e) {
                LOG.warn("Illegal argument passed to be printed on System Recorder: " + "Message " + message + ";" + " Category " + category + ";" + " Source " + source + ";" + " EntityName "
                        + entityName + ";" + " Infos " + hostname + "| " + infos);
            }
        }
    }

    /**
     * Print Error and Warnings on System Recorder (Credential Manager Service)
     * 
     * @param message
     * @param category
     * @param source
     * @param entityName
     * @param infos
     */

    public void printErrorOnSystemRecorder(final String message, final ErrorSeverity category, final String source, final String entityName, String infos) {
        if (infos == null) {
            infos = "";
        }
        String hostname = null;
        try {
            InetAddress host = InetAddress.getLocalHost();
            hostname = host.getHostName();
        } catch (UnknownHostException e1) {
            hostname = "";
        }
        System.out.println("SYSTEM RECORDER ERROR = { (s):" + source + "-(m):" + message + "-(e):" + entityName + "-(i):" + hostname + "| " + infos + " }");
        if (this.credMService != null) {
            try {
                this.credMService.printErrorOnRecorder(message, category, source, entityName, hostname + " - " + infos);
            } catch (final IllegalArgumentException e) {
                LOG.warn("Illegal argument passed to be printed on System Recorder: " + "Message " + message + ";" + " Category " + category + ";" + " Source " + source + ";" + " EntityName "
                        + entityName + ";" + " Infos " + hostname + "| " + infos);
            }
        }
    }

    /**
     * @param keys
     * @return
     */
    public CredentialManagerPIBParameters getPibParameters() {

        if (this.credMService != null) {
            return this.credMService.getPibParameters();
        }
        return new CredentialManagerPIBParameters();
    }

    public List<CredentialManagerX500CertificateSummary> getCertificatesByEntityName(String entityName, CredentialManagerEntityType entityType, CredentialManagerCertificateStatus... certificateStatus)
            throws CertificateNotFoundException, GetCertificatesByEntityNameException, EntityNotFoundException {

        List<CredentialManagerX500CertificateSummary> credmManX500CertSumList = null;

        switch (this.mode) {
        case SECURE_CHANNEL: {
            if (this.credMService != null) {
                try {
                    credmManX500CertSumList = this.credMService.listCertificatesSummary(entityName, entityType, certificateStatus);
                } catch (final CredentialManagerCertificateNotFoundException e) {
                    LOG.error("CredMService Certificate Not Found");
                    throw new CertificateNotFoundException(e.getMessage());
                } catch (final CredentialManagerEntityNotFoundException e) {
                    LOG.error("CredMService Entity Not Found");
                    throw new EntityNotFoundException(e.getMessage());
                } catch (final CredentialManagerInternalServiceException e) {
                    LOG.error("CredMService Internal Error");
                    throw new GetCertificatesByEntityNameException(e.getMessage());
                }
            }
        }
            break;
        case REST_CHANNEL:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new GetCertificatesByEntityNameException("Invalid method calling"));
            // break;
        default:
            LOG.error(ErrorMsg.API_ERROR_SERVICE_REST_INVALID_METHOD);
            throw (new GetCertificatesByEntityNameException("Invalid method calling"));
            // break;
        }

        return credmManX500CertSumList;

    }
} // end of class CredMServiceWrapper
