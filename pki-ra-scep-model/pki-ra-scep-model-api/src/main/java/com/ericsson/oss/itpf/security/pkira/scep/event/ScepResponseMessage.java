package com.ericsson.oss.itpf.security.pkira.scep.event;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pkira.scep.constants.ScepModelConstant;

/**
 *
 * ScepResponseMessage is the responseMessage holder for a given pkcs request. The ScepResponseMessage will have Certificate, TransactionId and Status in case of successful generation of a Certificate
 * for a given request. ScepResponseMessage will contain the TransactionId, Status and FailureInfo if the certificate generation fails
 *
 * @author xananer
 */

// This event is deprecated and should not be used further.
@EModel(namespace = "pki-ra-scep", name = "ScepReponse", version = ScepModelConstant.MODEL_VERSION, description = "Scep Response Message")
@EventTypeDefinition(channelUrn = "//global/ClusteredScepResponseChannel")
public class ScepResponseMessage {

    @EModelAttribute(description = "transactionId to be send over the Response Channel", mandatory = true)
    @EventAttribute(filterable = false)
    private String transactionId;

    @EModelAttribute(description = "status to be send over the Response Channel", mandatory = true)
    @EventAttribute(filterable = false)
    private int status;

    @EModelAttribute(description = "certificate to be send over the Response Channel", mandatory = false)
    @EventAttribute(filterable = false)
    private byte[] certificate;

    @EModelAttribute(description = "failureInfo to be send over the Response Channel", mandatory = false)
    @EventAttribute(filterable = false)
    private String failureInfo;

    /**
     * @return the failureInfo
     */
    public String getFailureInfo() {
        return failureInfo;
    }

    /**
     * @param failureInfo
     *            the failureInfo to set
     */
    public void setFailureInfo(final String failureInfo) {
        this.failureInfo = failureInfo;
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
    public void setTransactionId(final String transactionId) {
        this.transactionId = transactionId;
    }

    /**
     * @return the status
     */
    public int getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final int status) {
        this.status = status;
    }

    /**
     * @return the certificate
     */
    public byte[] getCertificate() {
        return certificate;
    }

    /**
     * @param certificate
     *            the certificate to set
     */
    public void setCertificate(final byte[] certificate) {
        this.certificate = certificate;
    }

}
