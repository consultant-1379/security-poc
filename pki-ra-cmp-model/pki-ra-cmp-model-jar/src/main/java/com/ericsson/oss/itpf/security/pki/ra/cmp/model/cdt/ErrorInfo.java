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
 * This class defines a complexDataType named ErrorInfo in encoded format
 * containing errorMessage .
 * 
 * @author tcsdemi
 *
 */

@EModel(description = "This Model defines a complexDataType ErrorInfo in encoded format containing errorMessage", namespace =CMPModelConstants.CMP_NAMESPACE, name = "ErrorInfo", version = CMPModelConstants.VERSION)
@CdtDefinition
public class ErrorInfo implements Serializable {

    private static final long serialVersionUID = 2593934280676148472L;

    @EModelAttribute(description = "This attribute is error code.", mandatory = true)
    @CdtAttribute
    private String errorMessage;

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(final String errorMessage) {
        this.errorMessage = errorMessage;
    }

}
