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
package com.ericsson.oss.itpf.security.pki.cdps.common;

import java.security.cert.X509CRL;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.cdps.common.constant.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;
import com.ericsson.oss.itpf.security.pki.common.util.CRLUtility;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CRLConversionException;
import com.ericsson.oss.itpf.security.pki.common.validator.X509CRLValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLExpiredException;

/**
 * This class is used to handles the persistence operations using PersistenceManager class and send corresponding response
 * 
 * @author xjagcho
 *
 */
public class CDPSPersistenceHandler {

    @Inject
    private Logger logger;

    @Inject
    private PersistenceManager persistenceManager;

    @Inject
    private X509CRLValidator x509CRLValidator;

    @Inject
    private SystemRecorder systemRecorder;

    private static final String CA_NAME = "caName";
    private static final String CERT_SERIALNUMBER = "certSerialNumber";

    /**
     * This method will hand over getCRL request to corresponding persistenceManager based on the caName and certSerialNumber. The persistenceManager class processes the getCrl request and returns the
     * appropriate response.
     * 
     * @param caName
     *            name of the CA which is the issuer of the CRL
     * @param caCertSerialNumber
     *            which is the certificate serial number of the CACertificate by which the CRL is issued
     * @return byte[] which contains CRL byte array.
     * @throws CRLConversionException
     *             will be thrown in case of Failing in converting CRL byte array
     * @throws CRLDistributionPointServiceException
     *             will be thrown when an exception occurs while processing the request to persist.
     * @throws CRLExpiredException
     *             will be thrown in case of CRL is expired.
     * @throws CRLNotFoundException
     *             will be thrown when an exception occurs CRL is not found with give caName and certSerialNumber in DB.
     */
    @Profiled
    public byte[] getCRL(final String caName, final String certSerialNumber) throws CRLConversionException, CRLDistributionPointServiceException, CRLExpiredException, CRLNotFoundException {
        logger.debug("getCRL method in PersistenceHandler class");
        try {

            final Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(CA_NAME, caName);
            parameters.put(CERT_SERIALNUMBER, certSerialNumber);

            final List<CDPSEntityData> cdpsCrlEntityList = persistenceManager.findEntitiesWhere(CDPSEntityData.class, parameters);

            if (ValidationUtils.isNullOrEmpty(cdpsCrlEntityList)) {
                logger.error(ErrorMessages.ERR_CRL_NOT_FOUND);
                systemRecorder.recordError("PKI_CDPS.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLClient", "CRLDownload", "Couldn't find the CRL in CDPS Service with the CAName :" + caName
                        + " and Certificate Serial Number :" + certSerialNumber);
                
                throw new CRLNotFoundException(ErrorMessages.ERR_CRL_NOT_FOUND);
            }

            final byte[] crlByteArray = cdpsCrlEntityList.get(0).getCrl();

            final X509CRL x509crl = CRLUtility.getX509CRL(crlByteArray);
            x509CRLValidator.checkCRLvalidity(x509crl);

            return crlByteArray;

        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.ERR_INTERNAL_ERROR, persistenceException);
            systemRecorder.recordError("PKI_CDPS.DB_ERROR", ErrorSeverity.ERROR, "CDPSDBService", "CRLDownload", "Exception occured while retrieving the CRL in CDPS Service with the CAName :"
                    + caName + " and Certificate Serial Number :" + certSerialNumber);
            
            throw new CRLDistributionPointServiceException(ErrorMessages.ERR_INTERNAL_ERROR);
        }
    }
}