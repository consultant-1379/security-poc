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
package com.ericsson.oss.itpf.security.pki.manager.revocation.model.mapper;

import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;

/**
 * This class is mapper for CertificateIdentifierModel which is used to form CertificateIdentifierModel Object with all parameters set.
 * 
 * @author tcsramc
 *
 */
public class CertificateIdentifierModelMapper {
    /**
     * This method is responsible to form model Object with all required parameters.
     * 
     * @param certificateIdentifier
     *            from which required parameters has to extract and form model object
     * @return CertificateIdentifierModel
     */
    public RevocationRequest toRevocationRequest(final CertificateIdentifier certificateIdentifier) {
        final RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setIssuerName(certificateIdentifier.getIssuerName());
        revocationRequest.setSerialNumber(certificateIdentifier.getSerialNumber());
        return revocationRequest;
    }

    /**
     * This method is used to form CertificateIdentifier object from the event.
     * 
     * @param revocationRequest
     *            event from which we need to extract
     * @return CertificateIdentifier
     */
    public CertificateIdentifier toCertificateIdentifier(final RevocationRequest revocationRequest) {
        final CertificateIdentifier certificateIdentifier = new CertificateIdentifier();
        final String issuerName = revocationRequest.getIssuerName();
        final String serialNumber = revocationRequest.getSerialNumber();
        certificateIdentifier.setIssuerName(issuerName);
        certificateIdentifier.setSerialNumber(serialNumber);
        return certificateIdentifier;

    }

}
