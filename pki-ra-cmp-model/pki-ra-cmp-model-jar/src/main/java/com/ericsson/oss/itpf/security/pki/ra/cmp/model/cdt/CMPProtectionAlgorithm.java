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
package com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtDefinition;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class defines model for CMPProtectionAlgorithm. It is a complexDataType
 * which is declared in CMPServiceResponse. * ProtectionAlgorithm is sent to
 * PKI-RA for signing CMP messages, as part of an Event->CMPServiceResponse It
 * is an attribute of PKI Initialization or Key update request message received
 * at PKI-RA, which is dispatched via modeled event (CMPServiceRequest) to
 * PKI-Manager. At PKI-Manager Initialization Response and Key update response
 * are formed and sent to PKI-RA via a modeled event(CMPServiceResponse) for
 * signing.
 *
 * For Signing PKI response messages, protection Algorithm which was sent in
 * Request is to be used, hence , this attribute is included so that RA can
 * directly read it from modeled event.
 * 
 * @author tcsdemi
 *
 */
@EModel(description = "This Model defines a complexDataType CMPProtectionAlgorithm in encoded format", namespace =CMPModelConstants.CMP_NAMESPACE, name = "CMPProtectionAlgorithm", version = CMPModelConstants.VERSION)
@CdtDefinition
public class CMPProtectionAlgorithm implements Serializable {

    private static final long serialVersionUID = 849548850356616367L;

    @EModelAttribute(description = "The identity of this product.", mandatory = true)
    @CdtAttribute
    private byte[] cmpProtectionAlgorithm;

    public byte[] getCmpProtectionAlgorithm() {
        return cmpProtectionAlgorithm;
    }

    public void setCmpProtectionAlgorithm(final byte[] cmpProtectionAlgorithm) {
        this.cmpProtectionAlgorithm = cmpProtectionAlgorithm;
    }

}
