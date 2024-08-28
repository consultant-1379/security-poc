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
package com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.cdt.CertificateIdentifierModel;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.edt.RevocationReasonType;

/**
 * This class defines model for RevocationServiceRequest. Event contains <br/>
 * 1. CertificateIdentifierModel(which is an CDT having issuerName and serialNumber as parameters.) <br/>
 * 2. InvalidityDateModel(which is a CDT contains date)<br/>
 * 3. RevocationReasonType(which is an EDT defines the reason for revocation.)<br/>
 * 4. senderName<br/>
 * 5.transactionID.
 * 
 * @author tcsramc
 *
 */
@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, name = "RevocationServiceRequestEvent", version = CMPModelConstants.VERSION, description = "This Event contains parameters required for Certificate revocation,which will be sent to PKI-Manager.")
@EventTypeDefinition(channelUrn = "//global/ClusteredCMPServiceRequestChannel")
public class RevocationServiceRequestEvent implements Serializable {

    private static final long serialVersionUID = -3100055413364639876L;

    @EModelAttribute(description = "CertificateIdentifierRequest")
    @EventAttribute
    private CertificateIdentifierModel certificateIdentifierModel;

    @EModelAttribute(description = "transactionId")
    @EventAttribute
    private String transactionId;

    @EModelAttribute(description = "subjectName")
    @EventAttribute
    private String subjectName;

    @EModelAttribute(description = "revocationReasonType")
    @EventAttribute
    private RevocationReasonType revocationReasonType;

    @EModelAttribute(description = "invalidityDate")
    @EventAttribute
    private String invalidityDate;

    /**
     * @return the subjectName
     */
    public String getSubjectName() {
        return subjectName;
    }

    /**
     * @param subjectName
     *            the subjectName to set
     */
    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    /**
     * @return the invalidityDate
     */
    public String getInvalidityDate() {
        return invalidityDate;
    }

    /**
     * @param invalidityDate
     *            the invalidityDate to set
     */
    public void setInvalidityDate(String invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    /**
     * 
     * @return revocationReasonType
     */
    public RevocationReasonType getRevocationReasonType() {
        return revocationReasonType;
    }

    /**
     * @param revocationReasonType
     *            the revocationReasonType to set
     */
    public void setRevocationReasonType(RevocationReasonType revocationReasonType) {
        this.revocationReasonType = revocationReasonType;
    }

    /**
     * @return the transactionId
     */
    public String getTransactionId() {
        return transactionId;
    }

    /**
     * @param transactionId
     *            the transactionId to set
     */
    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    /**
     * @return the certificateIdentifierModel
     */
    public CertificateIdentifierModel getCertificateIdentifierModel() {
        return certificateIdentifierModel;
    }

    /**
     * @param certificateIdentifierModel
     *            the certificateIdentifierModel to set
     */
    public void setCertificateIdentifierModel(CertificateIdentifierModel certificateIdentifierModel) {
        this.certificateIdentifierModel = certificateIdentifierModel;
    }

}
