/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pkira.scep.cdt;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtDefinition;
import com.ericsson.oss.itpf.security.pkira.scep.constants.ScepModelConstant;

/**
 * This class defines model for CRL and is a complexDataType used to hold CRL data in encoded format. .
 * 
 * @author xchowja
 *
 */
@EModel(description = "This Model defines a complexDataType CRL in encoded format", namespace = ScepModelConstant.SCEP_NAMESPACE, name = "ScepCrl", version = ScepModelConstant.MODEL_VERSION)
@CdtDefinition
public class ScepCrl implements Serializable {

    private static final long serialVersionUID = -5454655505609054942L;

    @EModelAttribute(description = "This attribute is a byte array of CRL.", mandatory = true)
    @CdtAttribute
    private byte[] crlEncoded;

    public byte[] getCrlEncoded() {
        return crlEncoded;
    }

    public void setCrlEncoded(final byte[] crlEncoded) {
        this.crlEncoded = crlEncoded;
    }

}
