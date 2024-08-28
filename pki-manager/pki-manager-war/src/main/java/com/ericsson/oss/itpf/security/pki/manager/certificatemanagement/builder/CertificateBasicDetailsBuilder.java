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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter.CertificateBasicDetailsDTO;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * A builder class to build the Basic details of a certificate like certificateId,subjectDN,expiryDateFrom,expiryDateTo,issuer,entityTypes,keySize,signatureAlgorithm and certificateStatus in
 * certificate list JSON response.
 * 
 */
public class CertificateBasicDetailsBuilder {

    protected long id;
    protected EntityType type;
    protected String subject;
    protected Date notBefore;
    protected Date notAfter;
    protected CertificateStatus status;
    protected String issuer;
    protected long keySize;
    protected String signatureAlgorithm;
    protected String serialNumber;

    /**
     * builder method for setting serialNumber property
     *
     * @param serialNumber
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder serialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    /**
     * builder method for setting id property
     *
     * @param id
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder id(final long id) {

        this.id = id;
        return this;

    }

    /**
     * builder method for setting type property
     * 
     * @param type
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder type(final EntityType type) {

        this.type = type;
        return this;

    }

    /**
     * builder method for setting subject property
     * 
     * @param subject
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder subject(final String subject) {

        this.subject = subject;
        return this;

    }

    /**
     * builder method for setting notBefore property
     * 
     * @param notBefore
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder notBefore(final Date notBefore) {

        this.notBefore = notBefore;
        return this;

    }

    /**
     * builder method for setting notAfter property
     * 
     * @param notAfter
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder notAfter(final Date notAfter) {

        this.notAfter = notAfter;
        return this;

    }

    /**
     * builder method for setting status property
     * 
     * @param status
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder status(final CertificateStatus status) {

        this.status = status;
        return this;

    }

    /**
     * builder method for setting issuer property
     * 
     * @param issuer
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder issuer(final String issuer) {

        this.issuer = issuer;
        return this;

    }

    /**
     * builder method for setting keySize property
     * 
     * @param keySize
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder keySize(final long keySize) {

        this.keySize = keySize;
        return this;

    }

    /**
     * builder method for setting signatureAlgorithm property
     * 
     * @param signatureAlgorithm
     * @return DetailsBuilder
     */
    public CertificateBasicDetailsBuilder signatureAlgorithm(final String signatureAlgorithm) {

        this.signatureAlgorithm = signatureAlgorithm;
        return this;

    }

    /**
     * Return fully build basic details of Certificate Object.
     *
     * @return {@link CertificateBasicDetailsDTO} Object.
     */
    public CertificateBasicDetailsDTO build() {

        final CertificateBasicDetailsDTO details = new CertificateBasicDetailsDTO();
        details.setId(id);
        details.setType(type);
        details.setNotAfter(notAfter);
        details.setNotBefore(notBefore);
        details.setStatus(status);
        details.setSubject(subject);
        details.setIssuer(issuer);
        details.setKeySize(keySize);
        details.setSignatureAlgorithm(signatureAlgorithm);
        details.setSerialNumber(serialNumber);

        return details;
    }

}
