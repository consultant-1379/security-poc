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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;

import javax.xml.bind.annotation.*;

/**
 * This class represents algorithm. There are three types {@link CredentialManagerAlgorithmType}
 * of algorithms exists in our system. Key Generation algorithms contains the
 * key sizes. Name and Key Size are unique.
 */
@XmlRootElement(name = "Algorithm")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Algorithm", propOrder = { "name", "keySize", "type", "oid", "supported" })
public class CredentialManagerAlgorithm implements Serializable {

    private static final long serialVersionUID = 6753642248583064676L;

    @XmlAttribute(name = "Id", required = false)
    protected long id;
    @XmlElement(name = "Name", required = true)
    protected String name;
    /**
     * AlgorithmType has to be used only for retrieving Algorithms. Do not set
     * this value while updating Algorithm. Even if it is set, it will be
     * ignored.
     */
    @XmlElement(name = "Type", required = false)
    protected CredentialManagerAlgorithmType type;

    /**
     * OID has to be used only for retrieving Algorithms. Do not set this value
     * while updating Algorithm. Even if it set will be ignored.
     */
    @XmlElement(name = "OID", required = false)
    protected String oid;
    @XmlElement(name = "Supported", required = false)
    protected boolean supported;
    /**
     * KeySize has value only for key generation algorithms and for other type
     * of algorithms the value is null.If trying to update Key Generation
     * algorithms specify both algorithm name and key size. For other type of
     * algorithms only name is required and key size can be null.
     */
    @XmlElement(name = "KeySize", required = false)
    @XmlSchemaType(name = "positiveInteger")
    private Integer keySize;

    /**
     * @return the id
     */
    public long getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(final long id) {
        this.id = id;
    }

    /**
     * Returns algorithm name.
     * 
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the algorithm name.
     * 
     * @param name
     *            the name to set
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * Returns the algorithm type.
     * 
     * @return the type
     */
    public CredentialManagerAlgorithmType getType() {
        return type;
    }

    /**
     * Sets the algorithm type.
     * 
     * @param type
     *            the type to set
     */
    public void setType(final CredentialManagerAlgorithmType type) {
        this.type = type;
    }

    /**
     * Returns the algorithm oid.
     * 
     * @return the oid
     */
    public String getOid() {
        return oid;
    }

    /**
     * Sets the algorithm oid.
     * 
     * @param oid
     *            the oid to set
     */
    public void setOid(final String oid) {
        this.oid = oid;
    }

    /**
     * Returns true if algorithm is supported else false.
     * 
     * @return the supported
     */
    public boolean isSupported() {
        return supported;
    }

    /**
     * Set true if algorithm is supported else false.
     * 
     * @param supported
     *            the supported to set
     */
    public void setSupported(final boolean supported) {
        this.supported = supported;
    }

    /**
     * Returns the key size.
     * 
     * @return the keySize
     */
    public Integer getKeySize() {
        return keySize;
    }

    /**
     * Set KeySize value.
     * 
     * @param keySize
     *            the keySize to set
     */
    public void setKeySize(final Integer keySize) {
        this.keySize = keySize;
    }

    @Override
    public String toString() {
        return "Algorithm [name=" + name + ((null == type) ? "" : (", type=" + type)) + ", oid=" + oid + ", supported="
                + supported + ((null == keySize) ? "" : (", keySize=" + keySize)) + "]";
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((keySize == null) ? 0 : keySize.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((oid == null) ? 0 : oid.hashCode());
        result = prime * result + (supported ? 1231 : 1237);
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
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
        final CredentialManagerAlgorithm other = (CredentialManagerAlgorithm) obj;
        if (id != other.id) {
            return false;
        }
        if (keySize == null) {
            if (other.keySize != null) {
                return false;
            }
        } else if (!keySize.equals(other.keySize)) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (oid == null) {
            if (other.oid != null) {
                return false;
            }
        } else if (!oid.equals(other.oid)) {
            return false;
        }
        if (supported != other.supported) {
            return false;
        }
        if (type != other.type) {
            return false;
        }
        return true;
    }

}
