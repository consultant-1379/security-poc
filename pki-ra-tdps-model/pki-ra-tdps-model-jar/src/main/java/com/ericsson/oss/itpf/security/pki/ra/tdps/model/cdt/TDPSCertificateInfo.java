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
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

/**
 * This class defines a complex reference type which consists of a attributes required for a certificate to be published.
 * 
 * {@code HashMap<String,EncodedCertificate>}
 * 
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.EncodedCertificate
 * 
 * @author tcslant
 *
 */
@EModel(description = "This Model defines a complexDataType TrustsMap which defines certificate attributes.", namespace = TDPSModelConstants.NAME_SPACE, name = "TDPSCertificateInfo", version = TDPSModelConstants.VERSION)
@CdtDefinition
public class TDPSCertificateInfo implements Serializable {

    private static final long serialVersionUID = 9075086547392357946L;

    @EModelAttribute(description = "This attribute defines the  name of the entity.", mandatory = true)
    @CdtAttribute
    private String entityName;

    @EModelAttribute(description = "This attribute defines the  issuer name of the entity.", mandatory = true)
    @CdtAttribute
    private String issuerName;

    @EModelAttribute(description = "This attribute defines type of the entity.", mandatory = true)
    @CdtAttribute
    private TDPSEntityType tdpsEntityType;

    @EModelAttribute(description = "This attribute defines certificate serialNumber.", mandatory = true)
    @CdtAttribute
    private String serialNumber;

    @EModelAttribute(description = "This attribute is actual ByteArray of Certificate .", mandatory = true)
    @CdtAttribute
    private byte[] encodedCertificate;

    @EModelAttribute(description = "This attribute defines certificate serialNumber.", mandatory = true)
    @CdtAttribute
    private TDPSCertificateStatusType tdpsCertificateStatusType;

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public TDPSCertificateStatusType getTdpsCertificateStatusType() {
        return tdpsCertificateStatusType;
    }

    public void setTdpsCertificateStatusType(final TDPSCertificateStatusType tdpsCertificateStatusType) {
        this.tdpsCertificateStatusType = tdpsCertificateStatusType;
    }

    public byte[] getEncodedCertificate() {
        return encodedCertificate;
    }

    public void setEncodedCertificate(final byte[] encodedCertificate) {
        this.encodedCertificate = encodedCertificate;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getEntityName() {
        return entityName;
    }

    public void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    public TDPSEntityType getTdpsEntityType() {
        return tdpsEntityType;
    }

    public void setTdpsEntityType(final TDPSEntityType tdpsEntityType) {
        this.tdpsEntityType = tdpsEntityType;
    }

}
