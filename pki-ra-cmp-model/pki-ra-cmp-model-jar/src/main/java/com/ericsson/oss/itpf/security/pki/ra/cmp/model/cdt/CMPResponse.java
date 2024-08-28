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
 * This class is the actual CMPResponse which is received from entity. For
 * readability purpose a separate CDT is defined for response which is declared
 * in CMPServiceResponse as an emodel attribute. From CMPResponse,
 * IPResponseMessage is instantiated via parameterized constructor which takes
 * byte[] as an input.
 * 
 * @author tcsdemi
 *
 */
@EModel(description = "This Model defines a complexDataType CMPMessage in encoded format", namespace =CMPModelConstants.CMP_NAMESPACE, name = "CMPResponse", version = CMPModelConstants.VERSION)
@CdtDefinition
public class CMPResponse implements Serializable {

    private static final long serialVersionUID = 9075086547392357946L;

    @EModelAttribute(description = "This attribute is actual ByteArray of Response .", mandatory = true)
    @CdtAttribute
    private byte[] cmpResponseByteArray;

    public byte[] getCMPResponseByteArray() {
        return cmpResponseByteArray;
    }

    public void setCMPResponseByteArray(final byte[] cmpv2BaseMessage) {
        this.cmpResponseByteArray = cmpv2BaseMessage;
    }

}
