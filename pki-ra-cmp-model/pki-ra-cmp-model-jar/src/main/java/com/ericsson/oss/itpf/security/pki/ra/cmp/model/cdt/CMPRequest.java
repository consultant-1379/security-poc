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
 * This class is the actual CMPRequest which is received from entity. For readability purpose a separate CDT is defined for Request which is declared in CMPServiceRequest as an EmodelAttribute. From
 * CMPRequest, RequestMessage is instantiated via parameterized constructor which take byte[] as an input.
 * 
 * @author tcsdemi
 *
 */
@EModel(description = "This Model defines a complexDataType CMPMessage in encoded format", namespace = CMPModelConstants.CMP_NAMESPACE, name = "CMPRequest", version = CMPModelConstants.VERSION)
@CdtDefinition
public class CMPRequest implements Serializable {

    private static final long serialVersionUID = 538002619112288820L;

    @EModelAttribute(description = "This attribute is actual ByteArray of Request .", mandatory = true)
    @CdtAttribute
    private byte[] cmpRequestByteArray;

    /**
     * This returns the requestMessage in encoded form i,e in byte Array
     * 
     * @return
     */
    public byte[] getCmpRequestByteArray() {
        return cmpRequestByteArray;
    }

    /**
     * This sets the requestMessage in encoded form i,e in byte Array
     * 
     * @return
     */
    public void setCmpRequestByteArray(final byte[] cmpRequestByteArray) {
        this.cmpRequestByteArray = cmpRequestByteArray;
    }

}