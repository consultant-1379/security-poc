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

package com.ericsson.oss.itpf.security.pki.manager.model.profiles;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;

/**
 * <p>
 * This class holds the list of {@link TrustCAChain} and external CAs that can be trusted.
 *
 * <p>
 *
 * The following schema fragment specifies the XSD Schema of this class.
 *
 * <pre>
 * &lt;complexType name="TrustProfile">
 *  &lt;complexContent>
 *     &lt;extension base="{}AbstractProfile">
 *       &lt;sequence>
 *         &lt;element name="TrustCAChain" type="{}TrustCAChain" minOccuers="0" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *      &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 *
 */
@XmlRootElement(name = "TrustProfile")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrustProfile", propOrder = { "trustCAChains", "externalCAs" })
public class TrustProfile extends AbstractProfile implements Serializable {

    private static final long serialVersionUID = 1352653077975778186L;

    @XmlElement(name = "TrustCAChain")
    protected List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();

    @XmlElement(name = "ExternalCA")
    protected List<ExtCA> externalCAs = new ArrayList<ExtCA>();

    public TrustProfile() {
        setType(ProfileType.TRUST_PROFILE);
    }

    /**
     * @return the internalCADetails
     */
    public List<TrustCAChain> getTrustCAChains() {
        return trustCAChains;
    }

    /**
     * @param internalCADetails
     *            the internalCADetails to set
     */
    public void setTrustCAChains(final List<TrustCAChain> trustCAChains) {
        this.trustCAChains = trustCAChains;
    }

    /**
     * @return the externalCAEntities
     */
    public List<ExtCA> getExternalCAs() {
        return externalCAs;
    }

    /**
     * @param externalCAs
     *            the externalCAEntities to set
     */
    public void setExternalCAs(final List<ExtCA> externalCAs) {
        this.externalCAs = externalCAs;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + (trustCAChains == null ? 0 : trustCAChains.hashCode());
        result = prime * result + (externalCAs == null ? 0 : externalCAs.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "TrustProfile [" + super.toString() + ", " + (null != trustCAChains ? "internalCAEntities=" + trustCAChains + ", " : "") + (null != externalCAs ? "externalCAs=" + externalCAs : "")
                + "]";
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
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final TrustProfile other = (TrustProfile) obj;
        final List<String> thisExternalCAs = new ArrayList<String>();
        for (final ExtCA extCA : externalCAs) {
            thisExternalCAs.add(extCA.getCertificateAuthority().getName());
        }
        final List<String> otherExternalCAs = new ArrayList<String>();
        for (final ExtCA extCA : other.externalCAs) {
            otherExternalCAs.add(extCA.getCertificateAuthority().getName());
        }
        if (thisExternalCAs.size() != otherExternalCAs.size()) {
            return false;
        }
        boolean isExternalMatched = false;
        for (final String thisExternalCA : thisExternalCAs) {
            for (final String otherExternalCA : otherExternalCAs) {
                if (thisExternalCA.equals(otherExternalCA)) {
                    isExternalMatched = true;
                    break;
                }
            }
            if (!isExternalMatched) {
                return false;
            }
            isExternalMatched = false;
        }
        if (trustCAChains == null) {
            if (other.trustCAChains != null) {
                return false;
            }
        } else if (other.trustCAChains == null) {
                return false;
        } else {
            if (trustCAChains.size() != other.trustCAChains.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final TrustCAChain trustCAChain : trustCAChains) {
                for (final TrustCAChain trustCAChainOther : other.trustCAChains) {
                    if (trustCAChain.equals(trustCAChainOther)) {
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
