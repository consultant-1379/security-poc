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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter;

import java.io.Serializable;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.fasterxml.jackson.annotation.JsonFilter;

/**
 * Class is used for apply the JSON filter and return the basic details of certificate like certificateId,subjectDN,expiryDateFrom,expiryDateTo,issuer,entityTypes,keySize,signatureAlgorithm and
 * certificateStatus in JSON response.
 * 
 */
@JsonFilter("details")
public class CertificateBasicDetailsDTO implements Serializable {

    private static final long serialVersionUID = 1L;
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
     * @return the id
     */
    public long getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(final long id) {
        this.id = id;
    }

    /**
     * @return the type
     */
    public EntityType getType() {
        return type;
    }

    /**
     * @param type
     *            the type to set
     */
    public void setType(final EntityType type) {
        this.type = type;
    }

    /**
     * @return the subject
     */
    public String getSubject() {
        return subject;
    }

    /**
     * @param subject
     *            the subject to set
     */
    public void setSubject(final String subject) {
        this.subject = subject;
    }

    /**
     * @return the notBefore
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     * @param notBefore
     *            the notBefore to set
     */
    public void setNotBefore(final Date notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * @return the notAfter
     */
    public Date getNotAfter() {
        return notAfter;
    }

    /**
     * @param notAfter
     *            the notAfter to set
     */
    public void setNotAfter(final Date notAfter) {
        this.notAfter = notAfter;
    }

    /**
     * @return the status
     */
    public CertificateStatus getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final CertificateStatus status) {
        this.status = status;
    }

    /**
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * @param issuer
     *            the issuer to set
     */
    public void setIssuer(final String issuer) {
        this.issuer = issuer;
    }

    /**
     * @return the keysize
     */
    public long getKeySize() {
        return keySize;
    }

    /**
     * @param keysize
     *            the keysize to set
     */
    public void setKeySize(final long keySize) {
        this.keySize = keySize;
    }

    /**
     * @return the signatureAlgorithm
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm
     *            the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(final String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the serialNumber
     */
    public String getSerialNumber(){
        return serialNumber;
    }
}
