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
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.constants.TDPSModelConstants;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;

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
@EModel(namespace = TDPSModelConstants.NAME_SPACE, name = "TDPSCertificateEvent", version = TDPSModelConstants.VERSION, description = "This event is used to send certificateInfo which needs to be either published to Trust distribution or un-prublished from trust distribution")
@EventTypeDefinition(channelUrn = TDPSModelConstants.CERTIFICATE_EVENT_CHANNEL_URN)
public class TDPSCertificateEvent implements Serializable {

    private static final long serialVersionUID = -1796106500551437049L;

    @EModelAttribute(description = "This attribute is used to define whether 'TDPSCertificateInfo' is to be published to Trust distribution point or not. ")
    @EventAttribute(filterable = true)
    private TDPSOperationType tdpsOperationType;

    @EModelAttribute(description = "This attribute consists of all attributes related to Certificate like, entityName, entityType, certificateSerialNo, encoded certificate.")
    @EventAttribute(filterable = true)
    private List<TDPSCertificateInfo> tdpsCertificateInfos;

    public List<TDPSCertificateInfo> getTdpsCertificateInfos() {
        return tdpsCertificateInfos;
    }

    public void setTdpsCertificateInfos(List<TDPSCertificateInfo> tdpsCertificateInfos) {
        this.tdpsCertificateInfos = tdpsCertificateInfos;
    }

    public TDPSOperationType getTdpsOperationType() {
        return tdpsOperationType;
    }

    public void setTdpsOperationType(final TDPSOperationType tdpsOperationType) {
        this.tdpsOperationType = tdpsOperationType;
    }

}
