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
package com.ericsson.oss.itpf.security.pki.cdps.impl;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.*;
import com.ericsson.oss.itpf.security.pki.cdps.common.CDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.cdps.common.constant.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CRLConversionException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLExpiredException;

/**
 * This class is used to handles the persistence operations using PersistenceManager class and send corresponding response
 * 
 * @author xjagcho
 *
 */
public class CRLDistributionPointServiceManager {

    @Inject
    private CDPSPersistenceHandler cdpsPersistenceHandler;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method will hand over getCRL request to corresponding persistenceHandler based on the caName and certSerialNumber. The persistenceManager class processes the getCrl request and returns the
     * appropriate response.
     * 
     * @param caName
     *            name of the CA which is the issuer of the CRL
     * @param caCertSerialNumber
     *            which is the certificate serial number of the CACertificate by which the CRL is issued
     * @return byte[] which contains CRL byte array.
     * @throws CRLDistributionPointServiceException
     *             will be thrown when an exception occurs while processing the request to persist.
     * @throws CRLNotFoundException
     *             will be thrown when an exception occurs CRL is not found with give caName and certSerialNumber in DB.
     * @throws InvalidCRLException
     *             will be thrown when the system encounters an Invalid CRL.
     */
    @Profiled
    public byte[] getCRL(final String caName, final String certSerialNumber) throws CRLDistributionPointServiceException, CRLNotFoundException, InvalidCRLException {
        byte[] crl = null;
        try {
            crl = cdpsPersistenceHandler.getCRL(caName, certSerialNumber);
            systemRecorder.recordEvent("PKI_CDPS.CRL_RETRIVED", EventLevel.COARSE, "CDPSService", "CRLClient", "Requested CRL retrived from CDPS DB Service with the CAName :" + caName
                    + " and Certificate Serial Number :" + certSerialNumber);
        } catch (CRLConversionException crlConversionException) {
            systemRecorder.recordError("PKI_CDPS.CRL_CONVERSION_ERROR", ErrorSeverity.ERROR, "CRLClient", "CRLDownload", "Couldn't convert the CRL byte to X509 CRL for the CAName :" + caName
                    + " and Certificate Serial Number :" + certSerialNumber);
            throw new InvalidCRLException(ErrorMessages.ERR_CRL_CONVERSION, crlConversionException);
        } catch (CRLExpiredException crlExpiredException) {
            systemRecorder.recordSecurityEvent("CRLDistributionPointServiceManager", "CDPSService", "Requested CRL is Expired in CDPS Service with the CAName :" + caName + " and Certificate Serial Number :"
                    + certSerialNumber, "CRLExpired", ErrorSeverity.ERROR, "FAILURE");
            throw new InvalidCRLException(ErrorMessages.ERR_CRL_EXPIRED, crlExpiredException);
        }

        return crl;
    }
}