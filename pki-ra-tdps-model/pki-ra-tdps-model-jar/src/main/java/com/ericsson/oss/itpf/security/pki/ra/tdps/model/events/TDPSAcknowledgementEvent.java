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
package com.ericsson.oss.itpf.security.pki.ra.tdps.model.events;

import java.io.Serializable;
import java.util.List;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSErrorInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.constants.TDPSModelConstants;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;

/**
 * This is a modeled event for sending Certificate details like entitytype/Name/certificate serialNo/x509Certificate in encoded format to pki-ra whenever there is a publish or un-publish certificate
 * to TDPS.
 * 
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.EncodedCertificate
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType
 * 
 * @author tcslant
 *
 */
@EModel(namespace = TDPSModelConstants.NAME_SPACE, name = "TDPSAcknowledgementEvent", version = TDPSModelConstants.VERSION, description = "This event is used to send certificateInfo which needs to be ..")
@EventTypeDefinition(channelUrn = TDPSModelConstants.ACKNOWLEDGE_CHANNEL_URN)
public class TDPSAcknowledgementEvent implements Serializable {

    private static final long serialVersionUID = 5648868250669943589L;

    @EModelAttribute(description = "This attribute defines whether the response sent is Failure or success response.")
    @EventAttribute(filterable = true)
    private TDPSResponseType responseType;

    @EModelAttribute(description = "This attribute is used to define whether this acknowledgement is for publish operation or for unpublish operation ")
    @EventAttribute(filterable = true)
    private TDPSOperationType tdpsOperationType;

    @EModelAttribute(description = "This attribute defines the error message. If 'TDPSResponseType' is FAILURE then at "
            + "PKI-RA errorInfo can be extracted and then proper Failure message can be formed")
    @EventAttribute(filterable = true)
    private TDPSErrorInfo errorInfo;

    @EModelAttribute(description = "This attribute is a List which stores Certificate information for all entities(CA and Entity)")
    @EventAttribute(filterable = true)
    private List<TDPSCertificateInfo> tdpsCertificateInfoList;

    /**
     * @return the tdpsOperationType
     */
    public TDPSOperationType getTdpsOperationType() {
        return tdpsOperationType;
    }

    /**
     * @param tdpsOperationType
     *            the tdpsOperationType to set
     */
    public void setTdpsOperationType(TDPSOperationType tdpsOperationType) {
        this.tdpsOperationType = tdpsOperationType;
    }

    /**
     * @return the responseType
     */
    public TDPSResponseType getResponseType() {
        return responseType;
    }

    /**
     * @param responseType
     *            the responseType to set
     */
    public void setResponseType(final TDPSResponseType responseType) {
        this.responseType = responseType;
    }

    /**
     * @return the errorInfo
     */
    public TDPSErrorInfo getErrorInfo() {
        return errorInfo;
    }

    /**
     * @param errorInfo
     *            the errorInfo to set
     */
    public void setErrorInfo(final TDPSErrorInfo errorInfo) {
        this.errorInfo = errorInfo;
    }

    /**
     * @return the tdpsCertificateInfoList
     */
    public List<TDPSCertificateInfo> getTdpsCertificateInfoList() {
        return tdpsCertificateInfoList;
    }

    /**
     * @param tdpsCertificateInfoList
     *            the tdpsCertificateInfoList to set
     */
    public void setTdpsCertificateInfoList(final List<TDPSCertificateInfo> tdpsCertificateInfoList) {
        this.tdpsCertificateInfoList = tdpsCertificateInfoList;
    }

}
