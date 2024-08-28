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
package com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity;

import java.io.Serializable;
import java.util.Arrays;

import javax.persistence.*;

/**
 * This is Entity class to map with table data
 * 
 * @author xjagcho
 *
 */
@Entity
@Table(name = "cdps_crl", uniqueConstraints = @UniqueConstraint(columnNames = { "ca_name", "cert_serial_number" }))
@NamedQueries({ @NamedQuery(name = "CDPSEntityData.findByCaNameAndSerialNumber", query = "SELECT c FROM CDPSEntityData c WHERE c.caName = :caName AND c.certSerialNumber = :serialNumber") })
public class CDPSEntityData implements Serializable {

    private static final long serialVersionUID = 6110447903932360053L;

    @Id
    @Column(name = "id")
    @SequenceGenerator(name = "SEQ_CDPS_CRL_ID_GENERATOR", sequenceName = "SEQ_CDPS_CRL_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_CDPS_CRL_ID_GENERATOR")
    private int id;

    @Column(name = "ca_name", nullable = false)
    private String caName;

    @Column(name = "cert_serial_number", nullable = false)
    private String certSerialNumber;

    @Column(name = "crl", nullable = false)
    private byte[] crl;

    /**
     * @return the id
     */
    public int getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(final int id) {
        this.id = id;
    }

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
     * @return the certSerialNumber
     */
    public String getCertSerialNumber() {
        return certSerialNumber;
    }

    /**
     * @param certSerialNumber
     *            the certSerialNumber to set
     */
    public void setCertSerialNumber(final String certSerialNumber) {
        this.certSerialNumber = certSerialNumber;
    }

    /**
     * @return the crl
     */
    public byte[] getCrl() {
        return crl;
    }

    /**
     * @param crl
     *            the crl to set
     */
    public void setCrl(final byte[] crl) {
        this.crl = crl;
    }

    /**
     * This method returns hash code of the CDPSEntityData object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((caName == null) ? 0 : caName.hashCode());
        result = prime * result + ((certSerialNumber == null) ? 0 : certSerialNumber.hashCode());
        result = prime * result + Arrays.hashCode(crl);
        result = prime * result + id;
        return result;
    }

    /**
     * This method checks the quality of the object
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CDPSEntityData other = (CDPSEntityData) obj;
        if (caName == null) {
            if (other.caName != null) {
                return false;
            }
        } else if (!caName.equals(other.caName)) {
            return false;
        }
        if (certSerialNumber == null) {
            if (other.certSerialNumber != null) {
                return false;
            }
        } else if (!certSerialNumber.equals(other.certSerialNumber)) {
            return false;
        }
        if (!Arrays.equals(crl, other.crl)) {
            return false;
        }
        if (id != other.id) {
            return false;
        }
        return true;
    }

    /**
     * This method prints the data of the class
     */
    @Override
    public String toString() {
        return "CDPSEntityData [id=" + id + ", caName=" + caName + ", certSerialNumber=" + certSerialNumber + ", crl=" + Arrays.toString(crl) + "]";
    }

}
