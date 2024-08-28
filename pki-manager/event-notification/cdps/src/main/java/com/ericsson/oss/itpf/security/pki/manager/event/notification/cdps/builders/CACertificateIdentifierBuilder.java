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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;

/**
 * This Class builds the list of CACertificateIdentifier object using caName and cerficateSerialNumber
 * 
 * @author xjagcho
 *
 */
public class CACertificateIdentifierBuilder {
    private String caName;
    private String cerficateSerialNumber;

    /**
     * This method sets caName
     * 
     * @return CACertificateIdentifierBuilder
     */
    public CACertificateIdentifierBuilder caName(final String caName) {
        this.caName = caName;
        return this;
    }

    /**
     * This method sets cerficateSerialNumber
     * 
     * @return CACertificateIdentifierBuilder
     */
    public CACertificateIdentifierBuilder cerficateSerialNumber(final String cerficateSerialNumber) {
        this.cerficateSerialNumber = cerficateSerialNumber;
        return this;
    }

    /**
     * This method builds the list CACertificateIdentifier using caName and cerficateSerialNumber
     * 
     * @return CACertificateIdentifier it contains caName and cerficateSerialNumber
     */
    public CACertificateIdentifier build() {
        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName(caName);
        caCertificateIdentifier.setCerficateSerialNumber(cerficateSerialNumber);
        return caCertificateIdentifier;
    }

}
