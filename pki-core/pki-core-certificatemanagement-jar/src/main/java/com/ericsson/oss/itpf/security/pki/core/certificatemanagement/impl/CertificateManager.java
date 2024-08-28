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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;

/**
 * This interface provides contract for all Certificate manager instances
 * 
 */
public interface CertificateManager {
    /**
     * This method returns the Certificate generated from {@link CertificateGenerationInfo} passed.
     * 
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} object
     * @return Certificate object.
     */
    Certificate generateCertificate(CertificateGenerationInfo certificateGenerationInfo);

}
