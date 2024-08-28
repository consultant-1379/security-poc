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

package com.ericsson.oss.itpf.security.pki.manager.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

/**
 * <p>
 * Java class for CustomConfigurations complex type.
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * <pre>
 * &lt;complexType name="CustomConfigurations">
 * &lt;complexContent>
 * &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 * &lt;sequence>
 * &lt;element name="CustomConfiguration" type="{}CustomConfiguration" maxOccurs="unbounded"/>
 * &lt;/sequence>
 * &lt;/restriction>
 * &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */

@XmlRootElement(name = "CustomConfigurations")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CustomConfigurations", propOrder = { "customConfigurations" })
public class CustomConfigurations implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 3676853469572658898L;

    @XmlElement(name = "CustomConfiguration", required = true)
    protected List<CustomConfiguration> customConfigurations = new ArrayList<CustomConfiguration>();

    /**
     * @return the list of CustomConfigurations
     */
    public List<CustomConfiguration> getCustomConfigurations() {
        return customConfigurations;
    }

    /**
     * @param customConfigurations
     *            the CustomConfiguration list to set
     */
    public void setCustomConfigurations(final List<CustomConfiguration> customConfigurations) {
        this.customConfigurations = customConfigurations;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CustomConfigurations [" + (null != customConfigurations ? "customConfigurations=" + customConfigurations : "") + "]";
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (customConfigurations == null ? 0 : customConfigurations.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
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
        final CustomConfigurations other = (CustomConfigurations) obj;
        if (customConfigurations == null) {
            if (other.customConfigurations != null) {
                return false;
            }
        } else if (other.customConfigurations == null) {
            return false;
        } else {
            if (customConfigurations.size() != other.customConfigurations.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CustomConfiguration customConfiguration : customConfigurations) {
                for (final CustomConfiguration customConfigurationOther : other.customConfigurations) {
                    if (customConfiguration.equals(customConfigurationOther)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        }
        return true;
    }
}
