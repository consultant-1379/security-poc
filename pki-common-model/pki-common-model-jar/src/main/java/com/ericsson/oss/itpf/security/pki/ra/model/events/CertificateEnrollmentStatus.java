/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.model.events;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.ra.model.common.constants.ModelConstants;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateType;

/**
 * This class defines model for CertificateEnrollmentStatus EventType. Event consists of: 1. nodeName as String 2. CertificateType 3. issuerName as String 4. CertificateEnrollmentStatusType
 * 
 * @author xgvgvgv
 *
 */
@EModel(namespace = ModelConstants.COMMON_MODEL_NAMESPACE, name = "CertificateEnrollmentStatus", version = ModelConstants.COMMON_MODEL_VERSION, description = "This event contains certificate enrollment status event information")
@EventTypeDefinition(channelUrn = "//global/ClusteredCertificateEnrollmentStatusTopic", timeToLive = 30 * 60 * 1000)
public class CertificateEnrollmentStatus implements Serializable {

    private static final long serialVersionUID = -4104980065625838358L;

    @EModelAttribute(description = "This attribute is the node name which is required to fetch from CMP Request Message")
    @EventAttribute
    private String nodeName;

    @EModelAttribute(description = "This attribute is the certificate type which is required to fetch from CMP Request Message")
    @EventAttribute
    private CertificateType certificateType;

    @EModelAttribute(description = "This attribute is the issuer name which is required to fetch from CMP Request Message")
    @EventAttribute
    private String issuerName;

    @EModelAttribute(description = "This attribute defines the certificate enrollment status")
    @EventAttribute
    private CertificateEnrollmentStatusType certificateEnrollmentStatusType;

    /**
     * @return the nodeName
     */
    public String getNodeName() {
        return nodeName;
    }

    /**
     * @param nodeName
     *            the nodeName to set
     */
    public void setNodeName(final String nodeName) {
        this.nodeName = nodeName;
    }

    /**
     * @return the certificateType
     */
    public CertificateType getCertificateType() {
        return certificateType;
    }

    /**
     * @param certificateType
     *            the certificateType to set
     */
    public void setCertificateType(final CertificateType certificateType) {
        this.certificateType = certificateType;
    }

    /**
     * @return the issuerName
     */
    public String getissuerName() {
        return issuerName;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public void setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @return the certificateEnrollmentStatusType
     */
    public CertificateEnrollmentStatusType getCertificateEnrollmentStatusType() {
        return certificateEnrollmentStatusType;
    }

    /**
     * @param certificateEnrollmentStatusType
     *            the certificateEnrollmentStatusType to set
     */
    public void setCertificateEnrollmentStatusType(final CertificateEnrollmentStatusType certificateEnrollmentStatusType) {
        this.certificateEnrollmentStatusType = certificateEnrollmentStatusType;
    }

    @Override
    public String toString() {
        return "CertificateEnrollmentStatus [nodeName=" + nodeName + ", certificateType=" + certificateType + ", issuerName=" + issuerName + ", certificateEnrollmentStatusType="
                + certificateEnrollmentStatusType + "]";
    }
}
