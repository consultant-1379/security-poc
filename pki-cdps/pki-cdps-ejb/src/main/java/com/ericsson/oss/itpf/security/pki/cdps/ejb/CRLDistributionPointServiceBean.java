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
package com.ericsson.oss.itpf.security.pki.cdps.ejb;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.cdps.api.CRLDistributionPointService;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.*;
import com.ericsson.oss.itpf.security.pki.cdps.impl.CRLDistributionPointServiceManager;



/**
 * CRLDistributionPointServiceBean-This bean class fetches the instance of PersistenceHandler . The request is then forwarded to the corresponding persistenceHandler class for further processing.
 *
 * @author xjagcho
 */
@Stateless
@Profiled
public class CRLDistributionPointServiceBean implements CRLDistributionPointService {
    @Inject
    private Logger logger;

    @Inject
    private CRLDistributionPointServiceManager crlDistributionPointServiceManager;

    /**
     * This method will hand over getCRL request to corresponding PersistenceHandler based on the caName and certSerialNumber. The PersistenceHandler class processes the getCrl request and returns the
     * appropriate CRL.
     * 
     * @param caName
     *            name of the CA which is the issuer of the CRL
     * @param caCertSerialNumber
     *            which is the certificate serial number of the CACertificate by which the CRL is issued
     * @return byte[] which contains CRL byte array.
     * @throws CRLDistributionPointServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws CRLNotFoundException
     *             will be thrown in case of CRL is not found.
     * @throws InvalidCRLException
     *             will be thrown when the system encounters an Invalid CRL.
     */
    @Override
    public byte[] getCRL(final String caName, final String certSerialNumber) throws CRLDistributionPointServiceException, CRLNotFoundException, InvalidCRLException {
        logger.debug("getCRL method in CRLDistributionPointServiceBean class");
        return crlDistributionPointServiceManager.getCRL(caName, certSerialNumber);
    }
}