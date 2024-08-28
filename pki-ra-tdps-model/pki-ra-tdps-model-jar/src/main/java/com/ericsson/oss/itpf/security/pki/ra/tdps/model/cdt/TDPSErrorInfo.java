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
package com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtDefinition;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.constants.TDPSModelConstants;

/**
 * This class defines a complex reference type for error message while service TDPS request.
 * 
 * @author tcslant
 *
 */
@EModel(description = "This Model defines a complexDataType ErrorInfo which contains errorMessage as String, in case of any errors while processing TDPS Request.", namespace = TDPSModelConstants.NAME_SPACE, name = "TDPSErrorInfo", version = TDPSModelConstants.VERSION)
@CdtDefinition
public class TDPSErrorInfo implements Serializable {

    private static final long serialVersionUID = 9183103874315911664L;

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
