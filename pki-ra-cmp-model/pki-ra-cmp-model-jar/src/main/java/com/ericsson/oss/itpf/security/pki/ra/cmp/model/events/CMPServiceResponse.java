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
package com.ericsson.oss.itpf.security.pki.ra.cmp.model.events;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.edt.ResponseType;

/**
 * This class defines model for CMPServiceResponse EventType. Event consists of: 1. CMPResponse(cmpResponse) as a CDT 2. CMPProtectionAlgorithm(protectionAlgorithm) as a CDT 3.
 * ResponseCode(responseCode) as an EDT 4. ResponseType(responseType) as an EDT 5. transactionID as String Kindly refer to javadocs of individual model definitions.6.syncResponse
 * 
 * @author tcsdemi
 *
 */

@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, name = "CMPServiceResponse", version = CMPModelConstants.VERSION, description = "This event contains Response that has been sent by PKI-Manager")
@EventTypeDefinition(channelUrn = "//global/ClusteredCMPServiceResponseChannel")
public class CMPServiceResponse implements Serializable {

    private static final long serialVersionUID = -4084108991622857777L;

    @EModelAttribute(description = "This is a Base64 encoded TransactionId and is maintained across a transaction initiated from Node, i.e from IR till PKIConf message")
    @EventAttribute
    private String transactionID;

    @EModelAttribute(description = "This is the actual PKIMessage which is to be sent over the queue CMPMessage is modeled as a ComplexDataType which consists of Encoded PKIMessage sent from EventSender")
    @EventAttribute
    private CMPResponse cmpResponse;

    @EModelAttribute(description = "This attribute is an byteArray for protection Algorithm .")
    @EventAttribute
    private CMPProtectionAlgorithm protectionAlgorithm;

    @EModelAttribute(description = "This attribute defines the actual ResponseType whether KUR or IP")
    @EventAttribute
    private ResponseType responseType;

    @EModelAttribute(description = "This attribute defines the error message. If responseType is ERRORED then at PKI-RA errorInfo can be extracted and then proper CMPFailureInfo message can be formed")
    @EventAttribute
    private ErrorInfo errorInfo;

    @EModelAttribute(description = "This attribute is the entity name which is required to fetch required RA Message entity from DB,alongwith transactionId")
    @EventAttribute
    private String entityName;

    @EModelAttribute(description = "This attribute defines if the response is synchronous")
    @EventAttribute
    private boolean syncResponse;

    public String getEntityName() {
        return entityName;
    }

    public void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    public ErrorInfo getErrorInfo() {
        return errorInfo;
    }

    public void setErrorInfo(final ErrorInfo errorInfo) {
        this.errorInfo = errorInfo;
    }

    public ResponseType getResponseType() {
        return responseType;
    }

    public void setResponseType(final ResponseType responseType) {
        this.responseType = responseType;
    }

    public CMPProtectionAlgorithm getProtectionAlgorithm() {
        return this.protectionAlgorithm;
    }

    public void setProtectionAlgorithm(final CMPProtectionAlgorithm protectionAlgorithm) {
        this.protectionAlgorithm = protectionAlgorithm;
    }

    public String getTransactionID() {
        return transactionID;
    }

    public void setTransactionID(final String transactionID) {
        this.transactionID = transactionID;
    }

    public CMPResponse getCmpResponse() {
        return cmpResponse;
    }

    public void setCmpResponse(final CMPResponse cmpResponse) {
        this.cmpResponse = cmpResponse;
    }

    public boolean isSyncResponse() {
        return syncResponse;
    }

    public void setSyncResponse(final boolean syncResponse) {
        this.syncResponse = syncResponse;
    }

}
