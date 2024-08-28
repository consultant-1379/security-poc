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
package com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.cdt;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtDefinition;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class is the cdt for CertificateIdentifier which contains all Certificate fields required for the certificate to revoke.
 * 
 * 
 * @author tcsramc
 *
 */
@EModel(description = "This Model defines a complexDataType for CertificateIdentifier", namespace = CMPModelConstants.CMP_NAMESPACE, name = "CertificateIdentifierModel", version = CMPModelConstants.VERSION)
@CdtDefinition
public class CertificateIdentifierModel implements Serializable {

    private static final long serialVersionUID = 538002619112288820L;

    @EModelAttribute(description = "issuerName")
    @CdtAttribute
    private String issuerName;

    @EModelAttribute(description = "Certificate SerialNumber")
    @CdtAttribute
    private String serialNumber;

    /**
     * @return the issuerName
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @return the serialNumber
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }
}