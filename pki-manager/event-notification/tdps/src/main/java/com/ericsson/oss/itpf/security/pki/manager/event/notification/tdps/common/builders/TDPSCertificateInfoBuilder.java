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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders;

import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

/**
 * This class is used for building CertificateInfo complex data type which is an event attribute in TDPServiceResponse and TDPSCertificateEvent
 * 
 * @author tcsdemi
 *
 */
public class TDPSCertificateInfoBuilder {
    private byte[] certificate;
    private String serialNumber;
    private String entityName;
    private TDPSCertificateStatusType certificateStatusType;
    private TDPSEntityType entityType;
    private String issuerName;

    /**
     * Sets the certificate in byte array for building CertificateInfo event
     * 
     * @param certificate
     * @return
     */
    public TDPSCertificateInfoBuilder certificate(final byte[] certificate) {
        this.certificate = certificate;
        return this;
    }

    /**
     * Sets the certificate in byte Array for building CertificateInfo event.
     * 
     * @param serialNumber
     * @return
     */
    public TDPSCertificateInfoBuilder serialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    /**
     * Sets the entityName for building CertificateInfo event.
     * 
     * @param entityName
     * @return
     */
    public TDPSCertificateInfoBuilder entityName(final String entityName) {
        this.entityName = entityName;
        return this;
    }

    /**
     * sets the certificateStatusType which can be ACTIVE/INACTIVE for building CertificateInfo event.
     * 
     * @param status
     * @return
     */
    public TDPSCertificateInfoBuilder tDPSCertificateStatusType(final TDPSCertificateStatusType status) {
        this.certificateStatusType = status;
        return this;
    }

    /**
     * sets the entityType which is either ENTITY or CA_ENTITY for building CertificateInfo event.
     * 
     * @param entityType
     * @return
     */
    public TDPSCertificateInfoBuilder entityType(final TDPSEntityType entityType) {
        this.entityType = entityType;
        return this;
    }

    /**
     * Sets the IssuerName required for building CertificateInfo event
     * 
     * @param issuerName
     * @return
     */
    public TDPSCertificateInfoBuilder issuerName(final String issuerName) {
        this.issuerName = issuerName;
        return this;
    }

    /**
     * This method builds TDPSCertificateInfo modeled event from the class attributes
     * 
     * @return
     */
    public TDPSCertificateInfo build() {
        final TDPSCertificateInfo tDPSCertificateInfo = new TDPSCertificateInfo();

        tDPSCertificateInfo.setEncodedCertificate(certificate);
        tDPSCertificateInfo.setEntityName(entityName);
        tDPSCertificateInfo.setSerialNumber(serialNumber);
        tDPSCertificateInfo.setTdpsEntityType(entityType);
        tDPSCertificateInfo.setTdpsCertificateStatusType(certificateStatusType);
        tDPSCertificateInfo.setIssuerName(issuerName);

        return tDPSCertificateInfo;
    }
}