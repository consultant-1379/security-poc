/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.cdps.local.service.api;

import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;

/**
 * This class provides interfaces to Publish/Unpublish CRL's
 * 
 * @author xchowja
 * 
 */
@EService
@Local
public interface CRLDistributionPointLocalService {
    /**
     * This method is used to publish crls.
     * 
     * @param crlInfoList
     *            it contains the CACertificateInfo it holds caName and serialNumber and encodedCRL
     * @return
     * @throws CRLDistributionPointServiceException
     *             is thrown if any internal service errors occurs like database related issues
     */
    void publishCRL(final List<CRLInfo> crlInfoList) throws CRLDistributionPointServiceException;

    /**
     * This method is used to unpublish the crls
     * 
     * @param caCertificateInfos
     *             it holds caName and serialNumber
     * @return
     * @throws CRLDistributionPointServiceException
     *             is thrown if any internal service errors occurs like database related issues
     */
    void unPublishCRL(final List<CACertificateInfo> caCertificateInfos) throws CRLDistributionPointServiceException;
}
