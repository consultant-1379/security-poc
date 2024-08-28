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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;

/**
 * This Class prepares the CRL Info to map using CRL Information object of common model
 * 
 * @author xjagcho
 *
 */
public class CRLInfoEventMapper {
    /**
     * This method process the caCertificateInfo object
     * 
     * @param crlInfo
     *            it holds CACertificateInfo it contains caName and serialNumber and encoded CRL
     * 
     * @return CRLInfo
     */
    public CRLInfo fromModel(final com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo crlInfoModel) {
        final CRLInfo crlInfo = new CRLInfo();
        crlInfo.setEncodedCRL(crlInfoModel.getCrl().getX509CRLHolder().getCrlBytes());
        return crlInfo;
    }
}