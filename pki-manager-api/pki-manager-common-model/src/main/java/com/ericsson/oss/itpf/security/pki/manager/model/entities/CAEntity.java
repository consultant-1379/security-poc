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

package com.ericsson.oss.itpf.security.pki.manager.model.entities;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

/**
 * <p>
 * This class extends Abstract Entity Class. These are the internal Certificate Authorities. This class holds various properties of a CA. A CAEntity
 * should be mapped to one entity profile. It must
 * contain Subject. Subject ALt Name is optional for a CA Entity.
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * <pre>
 * &lt;complexType name="CAEntity">
 * &lt;complexContent>
 * &lt;extension base="{}AbstractEntity">
 * &lt;sequence>
 * &lt;element name="certificateAuthority" type="{}CertificateAuthority" minOccurs="0"/>
 * &lt;element name="KeyGenerationAlgorithm" type="{}Algorithm" minOccurs="0"/>
 * &lt;/sequence>
 * &lt;/extension>
 * &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlRootElement(name = "CAEntity")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CAEntity", propOrder = { "keyGenerationAlgorithm", "certificateAuthority" })
public class CAEntity extends AbstractEntity implements Serializable {

    /**
	 *
	 */
    private static final long serialVersionUID = 26334851108885359L;

    @XmlElement(name = "KeyGenerationAlgorithm", required = true)
    protected Algorithm keyGenerationAlgorithm;
    @XmlElement(name = "CertificateAuthority", required = true)
    protected CertificateAuthority certificateAuthority;
    @XmlTransient
    protected List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();

    /**
	 *
	 */
    public CAEntity() {
        type = EntityType.CA_ENTITY;
    }

    /**
     * @return the keyGenerationAlgorithm
     */
    public Algorithm getKeyGenerationAlgorithm() {
        return keyGenerationAlgorithm;
    }

    /**
     * @param keyGenerationAlgorithm
     *            the keyGenerationAlgorithm to set
     */
    public void setKeyGenerationAlgorithm(final Algorithm keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
    }

    /**
     * @return the certificateAuthority
     */
    public CertificateAuthority getCertificateAuthority() {
        return certificateAuthority;
    }

    /**
     * @param certificateAuthority
     *            the certificateAuthority to set
     */
    public void setCertificateAuthority(final CertificateAuthority certificateAuthority) {
        this.certificateAuthority = certificateAuthority;
    }

    /**
     * @return the certificateProfiles
     */
    public List<CertificateProfile> getCertificateProfiles() {
        return certificateProfiles;
    }

    /**
     * @param certificateProfiles
     *            the certificateProfiles to set
     */
    public void setCertificateProfiles(final List<CertificateProfile> certificateProfiles) {
        this.certificateProfiles = certificateProfiles;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CAEntity [" + super.toString() + ", "
                + (null != keyGenerationAlgorithm ? "keyGenerationAlgorithm=" + keyGenerationAlgorithm + ", " : "")
                + (null != certificateAuthority ? "certificateAuthority=" + certificateAuthority : "")
                + (null != certificateProfiles ? "certificateProfiles=" + certificateProfiles : "") + "]";
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + (keyGenerationAlgorithm == null ? 0 : keyGenerationAlgorithm.hashCode());
        result = prime * result + (certificateAuthority == null ? 0 : certificateAuthority.hashCode());
        result = prime * result + (certificateProfiles == null ? 0 : certificateProfiles.hashCode());
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
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CAEntity other = (CAEntity) obj;
        if (certificateAuthority == null) {
            if (other.certificateAuthority != null) {
                return false;
            }
        } else if (!certificateAuthority.equals(other.certificateAuthority)) {
            return false;
        }

        if (keyGenerationAlgorithm == null) {
            if (other.keyGenerationAlgorithm != null) {
                return false;
            }
        } else if (!keyGenerationAlgorithm.equals(other.keyGenerationAlgorithm)) {
            return false;
        }

        if (certificateProfiles == null) {
            if (other.certificateProfiles != null) {
                return false;
            }
        } else if (other.certificateProfiles == null) {
            return false;
        } else {
            if (certificateProfiles.size() != other.certificateProfiles.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CertificateProfile certificateProfile : certificateProfiles) {
                for (final CertificateProfile certificateProfileOther : other.certificateProfiles) {
                    if (certificateProfile.equals(certificateProfileOther)) {
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
