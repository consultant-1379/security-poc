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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;

/**
 * This is interface class to generate a CRL for a Certificate Authority, IssuerCertificate and its Associated CrlGenerationInfo
 * 
 * @author xananer
 * 
 */
public interface CrlGenerator {
    /**
     * @param certificateAuthority
     * @param issuerCertificates
     * @param crlGenerationInfo
     * @return CRLInfo
     * 
     * @throws CRLServiceException
     *             Thrown when internal db error occurs.
     * @throws CRLGenerationException
     *             Thrown when internal error occurs while generating CRL
     * @throws InvalidCRLExtensionException
     *             Thrown when invalid CRL extension is found.
     * @throws RevocationServiceException
     */
    CRLInfo generateCRL(final CertificateAuthority certificateAuthority, final Certificate issuerCertificates, final CrlGenerationInfo crlGenerationInfo) throws CRLServiceException,
            CRLGenerationException, InvalidCRLExtensionException, RevocationServiceException;

}
