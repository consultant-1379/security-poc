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
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;

/**
 * This class defines model for TDPSServiceResponse Event which includes all the certificates for all entities.
 * 
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSErrorInfo
 *
 * @author tcsdemi
 *
 */
@EModel(namespace = TDPSModelConstants.NAME_SPACE, name = "TDPServiceResponse", version = TDPSModelConstants.VERSION, description = "This event is used to send all certificates with publish flag as true and active certificates from PKI-Manager ")
@EventTypeDefinition(channelUrn = TDPSModelConstants.RESPONSE_CHANNEL_URN)
public class TDPServiceResponse implements Serializable {

    private static final long serialVersionUID = -4084108991622857777L;

    @EModelAttribute(description = "This attribute defines whether the response sent is Failure or success response.")
    @EventAttribute(filterable = true)
    private TDPSResponseType responseType;

    @EModelAttribute(description = "This attribute defines the error message. If 'TDPSResponseType' is FAILURE then at "
            + "PKI-RA errorInfo can be extracted and then proper Failure message can be formed")
    @EventAttribute(filterable = true)
    private TDPSErrorInfo errorInfo;

    @EModelAttribute(description = "This attribute is a List which stores Certificate information for all entities(CA and Entity)")
    @EventAttribute(filterable = true)
    private List<TDPSCertificateInfo> tdpsCertificateInfoList;

    public List<TDPSCertificateInfo> getTdpsCertificateInfoList() {
        return tdpsCertificateInfoList;
    }

    public void setTdpsCertificateInfoList(final List<TDPSCertificateInfo> tdpsCertificateInfoList) {
        this.tdpsCertificateInfoList = tdpsCertificateInfoList;
    }

    public TDPSErrorInfo getErrorInfo() {
        return errorInfo;
    }

    public TDPSResponseType getResponseType() {
        return responseType;
    }

    public void setErrorInfo(final TDPSErrorInfo errorInfo) {
        this.errorInfo = errorInfo;
    }

    public void setResponseType(final TDPSResponseType responseType) {
        this.responseType = responseType;
    }

}
