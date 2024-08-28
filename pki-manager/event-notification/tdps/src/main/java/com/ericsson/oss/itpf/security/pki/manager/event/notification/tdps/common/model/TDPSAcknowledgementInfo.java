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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.model;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class holds all the information regarding any acknowledgement information from TDPS.
 * 
 * @author tcsdemi
 *
 */
public class TDPSAcknowledgementInfo {
    private String entityName;
    private String issuerName;
    private String serialNumber;
    private CertificateStatus certificateStatus;
    private EntityType entityType;
    private TDPSAcknowledgementStatus acknowledgementStatus;

    /**
     * @param acknowledgementStatus
     *            the acknowledgementStatus to set
     */
    public void setAcknowledgementStatus(final TDPSAcknowledgementStatus acknowledgementStatus) {
        this.acknowledgementStatus = acknowledgementStatus;
    }

    /**
     * @return the acknowledgementStatus
     */
    public TDPSAcknowledgementStatus getAcknowledgementStatus() {
        return acknowledgementStatus;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public void setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @return the issuerName
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param entityName
     *            the entityName to set
     */
    public void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    /**
     * @return the entityName
     */
    public String getEntityName() {
        return entityName;
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
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param certificateStatus
     *            the certificateStatus to set
     */
    public void setCertificateStatus(final CertificateStatus certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

    /**
     * @return the certificateStatus
     */
    public CertificateStatus getCertificateStatus() {
        return certificateStatus;
    }

    /**
     * @param entityType
     *            the entityType to set
     */
    public void setEntityType(final EntityType entityType) {
        this.entityType = entityType;
    }

    /**
     * @return the entityType
     */
    public EntityType getEntityType() {
        return entityType;
    }
}