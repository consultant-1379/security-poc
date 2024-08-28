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
 * CRLInfo is an Object to holds CACertificateInfo object and Encoded CRL byte array Used for sending CRL information to CDPS
 * 
 * @author xnarsir
 *
 */

@EModel(description = "This Model defines a complexDataType CRLInfo in encoded format", namespace = CDPSModelConstant.NAME_SPACE, name = "CRLInfo", version = CDPSModelConstant.MODEL_VERSION)
@CdtDefinition
public class CRLInfo implements Serializable {

    private static final long serialVersionUID = 538002619112288820L;

    @EModelAttribute(description = "This attribute is actual CACertificateInfo object of CRLInfo Request .", mandatory = true)
    @CdtAttribute
    private CACertificateInfo caCertificateInfo;

    @EModelAttribute(description = "This attribute is actual ByteArray of CRLInfo Request .", mandatory = true)
    @CdtAttribute
    private byte[] encodedCRL;

    /**
     * @return the caCertificateInfo
     */
    public CACertificateInfo getCaCertificateInfo() {
        return caCertificateInfo;
    }

    /**
     * @param caCertificateInfo
     *            the caCertificateInfo to set
     */
    public void setCaCertificateInfo(final CACertificateInfo caCertificateInfo) {
        this.caCertificateInfo = caCertificateInfo;
    }

    /**
     * @return the encodedCRL
     */
    public byte[] getEncodedCRL() {
        return encodedCRL;
    }

    /**
     * @param encodedCRL
     *            the encodedCRL to set
     */
    public void setEncodedCRL(final byte[] encodedCRL) {
        this.encodedCRL = encodedCRL;
    }

}