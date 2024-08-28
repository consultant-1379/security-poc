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
package com.ericsson.oss.itpf.security.pki.common.model.certificate.extension;

import java.io.Serializable;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * This class contains key identifier
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="KeyIdentifier">
 *   &lt;complexContent>
 *       &lt;sequence>
 *           &lt;element name="KeyIdentifier" type="{}nonEmptyString"/>
 *         &lt;element name="Algorithm" type="{}Algorithm"/>
 *       &lt;/sequence>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement(name = "KeyIdentifier")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KeyIdentifier", propOrder = { "keyIdentifer", "algorithm" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class KeyIdentifier implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -5535461146075536853L;

    @XmlElement(name = "KeyIdentifier", required = false)
    protected String keyIdentifer;
    @XmlElement(name = "Algorithm", required = true)
    protected Algorithm algorithm;

    /**
     * @return the keyIdentifer
     */
    public String getKeyIdentifer() {
        return keyIdentifer;
    }

    /**
     * @param keyIdentifer
     *            the keyIdentifer to set
     */
    public void setKeyIdentifer(final String keyIdentifer) {
        this.keyIdentifer = keyIdentifer;
    }

    /**
     * @return the algorithm
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * @param algorithm
     *            the algorithm to set
     */
    public void setAlgorithm(final Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "KeyIdentifier [keyIdentifer=" + keyIdentifer + ", algorithm=" + algorithm + "]";
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
        result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
        result = prime * result + ((keyIdentifer == null) ? 0 : keyIdentifer.hashCode());
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
        final KeyIdentifier other = (KeyIdentifier) obj;
        if (algorithm == null) {
            if (other.algorithm != null) {
                return false;
            }
        } else if (!algorithm.equals(other.algorithm)) {
            return false;
        }
        if (keyIdentifer == null) {
            if (other.keyIdentifer != null) {
                return false;
            }
        } else if (!keyIdentifer.equals(other.keyIdentifer)) {
            return false;
        }
        return true;
    }
}
