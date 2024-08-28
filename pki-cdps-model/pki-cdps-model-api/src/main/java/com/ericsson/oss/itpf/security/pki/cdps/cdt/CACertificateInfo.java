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
package com.ericsson.oss.itpf.security.pki.cdps.cdt;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtAttribute;
import com.ericsson.oss.itpf.modeling.annotation.cdt.CdtDefinition;
import com.ericsson.oss.itpf.security.pki.cdps.constants.CDPSModelConstant;

/**
 * PKI Manager uses this class CACertificateInfo for sending the CRLNotification to CDPS over a channel. CACertificateInfo holds CAName,CertificateSerialNumber
 * 
 * @author xnarsir
 *
 */

@EModel(description = "This Model defines a complexDataType CACertificateInfo in encoded format", namespace = CDPSModelConstant.NAME_SPACE, name = "CACertificateInfo", version = CDPSModelConstant.MODEL_VERSION)
@CdtDefinition
public class CACertificateInfo implements Serializable {

    private static final long serialVersionUID = 538002619112288820L;

    @EModelAttribute(description = "This attribute is actual String of CACertificateInfo Request .", mandatory = true)
    @CdtAttribute
    private String caName;

    @EModelAttribute(description = "This attribute is actual String of CACertificateInfo Request .", mandatory = true)
    @CdtAttribute
    private String certificateSerialNumber;

    /**
     * @return the caName
     */
    public String getCaName() {
        return caName;
    }

    /**
     * @param caName
     *            the caName to set
     */
    public void setCaName(final String caName) {
        this.caName = caName;
    }

    /**
     * @return the certificateSerialNumber
     */
    public String getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    /**
     * @param certificateSerialNumber
     *            the certificateSerialNumber to set
     */
    public void setCertificateSerialNumber(final String certificateSerialNumber) {
        this.certificateSerialNumber = certificateSerialNumber;
    }

}