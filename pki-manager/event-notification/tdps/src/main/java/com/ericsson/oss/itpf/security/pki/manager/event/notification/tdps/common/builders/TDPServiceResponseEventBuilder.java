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

import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.util.TrustMap;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

/**
 * This class is used to build TDPSResponseEvent
 * 
 * @author tcsdemi
 *
 */
public class TDPServiceResponseEventBuilder {

    private TDPSEntityType entityType;
    private Map<String, List<Certificate>> trustMap;

    /**
     * Sets the entityType whether CA or Entity
     * 
     * @param entityType
     * @return
     */
    public TDPServiceResponseEventBuilder entityType(final TDPSEntityType entityType) {
        this.entityType = entityType;
        return this;
    }

    /**
     * Sets the trusts related to each entity. Hence it is a Map with key as entityName and publishedCertificates as List
     * 
     * @param trustMap
     * @return
     */
    public TDPServiceResponseEventBuilder trustMap(final Map<String, List<Certificate>> trustMap) {
        this.trustMap = trustMap;
        return this;
    }

    /**
     * This builds the TDPServiceResponse (Modeled event) which is to be sent over eventBus
     * 
     * @return
     */
    public TDPServiceResponse build() {
        List<TDPSCertificateInfo> tdpsCertificateInfoList = TrustMap.get(entityType, trustMap);

        final TDPServiceResponse tDPServiceResponse = new TDPServiceResponse();

        tDPServiceResponse.setTdpsCertificateInfoList(tdpsCertificateInfoList);
        tDPServiceResponse.setResponseType(TDPSResponseType.SUCCESS);
        tDPServiceResponse.setErrorInfo(null);

        return tDPServiceResponse;
    }
}