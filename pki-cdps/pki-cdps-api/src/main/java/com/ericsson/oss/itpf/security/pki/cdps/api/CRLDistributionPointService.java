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
package com.ericsson.oss.itpf.security.pki.cdps.api;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.*;

/**
 * This is an interface for CDP Service and provides below operation.
 * <ul>
 * <li>handles the PKI CDPS getCRL request</li>
 * </ul>
 *
 * @author xjagcho
 */
@EService
public interface CRLDistributionPointService {
    /**
     * This method is used to get CRL byte array based on the caName and certSerialNumber from database.
     * 
     * @param caName
     *            name of the CA which is the issuer of the CRL.
     * @param caCertSerialNumber
     *            which is the Certificate Serial Number of the CACertificate by which the CRL is issued.
     * @return byte[] which contains CRL byte array.
     * @throws CRLDistributionPointServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws CRLNotFoundException
     *             will be thrown in case of CRL is not found with the given CA Name and CA Certificate Serial Number.
     * @throws InvalidCRLException
     *             will be thrown when the system encounters an Invalid CRL.
     */
    byte[] getCRL(final String caName, final String caCertSerialNumber) throws CRLDistributionPointServiceException, CRLNotFoundException, InvalidCRLException;
}
