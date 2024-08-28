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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

import java.io.Serializable;

import javax.xml.datatype.Duration;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;

/**
 * This class holds all the info required to generate a certificate by PKI Core. The values extracted from entity profile,certificate profile and CAEntity/Entity are overridden and final values are
 * placed in this class.
 * 
 * 
 */
public class CertificateGenerationInfo implements Serializable {

    private static final long serialVersionUID = 1198719385698646477L;

    protected long id;
    protected CertificateVersion version;
    protected Duration validity;
    protected boolean subjectUniqueIdentifier;
    protected boolean issuerUniqueIdentifier;
    protected Duration skewCertificateTime;
    protected Algorithm keyGenerationAlgorithm;
    protected Algorithm signatureAlgorithm;
    protected Algorithm issuerSignatureAlgorithm;
    protected CertificateExtensions certificateExtensions;
    protected CertificateRequest certificateRequest;
    protected CertificateAuthority issuerCA;
    protected CertificateAuthority cAEntityInfo;
    protected EntityInfo entityInfo;
    protected RequestType requestType;
    protected Certificate generatedCertificate;
    protected boolean forExternalCA;
    protected String subjectUniqueIdentifierValue;
    protected String issuerUniqueIdentifierValue;

    /**
     * @return the forExternalCA
     */
    public boolean isForExternalCA() {
        return forExternalCA;
    }

    /**
     * @param forExternalCA
     *            the forExternalCA to set
     */
    public void setForExternalCA(final boolean forExternalCA) {
        this.forExternalCA = forExternalCA;
    }

    /**
     * @return the version
     */
    public CertificateVersion getVersion() {
        return version;
    }

    /**
     * @param version
     *            the version to set
     */
    public void setVersion(final CertificateVersion version) {
        this.version = version;
    }

    /**
     * @return the validity
     */
    public Duration getValidity() {
        return validity;
    }

    /**
     * @param validity
     *            the validity to set
     */
    public void setValidity(final Duration validity) {
        this.validity = validity;
    }

    /**
     * @return the subjectUniqueIdentifier
     */
    public boolean isSubjectUniqueIdentifier() {
        return subjectUniqueIdentifier;
    }

    /**
     * @param subjectUniqueIdentifier
     *            the subjectUniqueIdentifier to set
     */
    public void setSubjectUniqueIdentifier(final boolean subjectUniqueIdentifier) {
        this.subjectUniqueIdentifier = subjectUniqueIdentifier;
    }

    /**
     * @return the issuerUniqueIdentifier
     */
    public boolean isIssuerUniqueIdentifier() {
        return issuerUniqueIdentifier;
    }

    /**
     * @param issuerUniqueIdentifier
     *            the issuerUniqueIdentifier to set
     */
    public void setIssuerUniqueIdentifier(final boolean issuerUniqueIdentifier) {
        this.issuerUniqueIdentifier = issuerUniqueIdentifier;
    }

    /**
     * @return the skewCertificateTime
     */
    public Duration getSkewCertificateTime() {
        return skewCertificateTime;
    }

    /**
     * @param skewCertificateTime
     *            the skewCertificateTime to set
     */
    public void setSkewCertificateTime(final Duration skewCertificateTime) {
        this.skewCertificateTime = skewCertificateTime;
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
     * @return the signatureAlgorithm
     */
    public Algorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm
     *            the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(final Algorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @return the issuerSignatureAlgorithm
     */
    public Algorithm getIssuerSignatureAlgorithm() {
        return issuerSignatureAlgorithm;
    }

    /**
     * @param issuerSignatureAlgorithm
     *            the issuerSignatureAlgorithm to set
     */
    public void setIssuerSignatureAlgorithm(final Algorithm issuerSignatureAlgorithm) {
        this.issuerSignatureAlgorithm = issuerSignatureAlgorithm;
    }

    /**
     * @return the certificateExtensions
     */
    public CertificateExtensions getCertificateExtensions() {
        return certificateExtensions;
    }

    /**
     * @param certificateExtensions
     *            the certificateExtensions to set
     */
    public void setCertificateExtensions(final CertificateExtensions certificateExtensions) {
        this.certificateExtensions = certificateExtensions;
    }

    /**
     * @return the cSR
     */
    public CertificateRequest getCertificateRequest() {
        return certificateRequest;
    }

    /**
     * @param cSR
     *            the cSR to set
     */
    public void setCertificateRequest(final CertificateRequest certificateRequest) {
        this.certificateRequest = certificateRequest;
    }

    /**
     * @return the issuerCA
     */
    public CertificateAuthority getIssuerCA() {
        return issuerCA;
    }

    /**
     * @param issuerCA
     *            the issuerCA to set
     */
    public void setIssuerCA(final CertificateAuthority issuerCA) {
        this.issuerCA = issuerCA;
    }

    /**
     * @return the cAEntityInfo
     */
    public CertificateAuthority getCAEntityInfo() {
        return cAEntityInfo;
    }

    /**
     * @param cAEntityInfo
     *            the cAEntityInfo to set
     */
    public void setCAEntityInfo(final CertificateAuthority cAEntityInfo) {
        this.cAEntityInfo = cAEntityInfo;
    }

    /**
     * @return the entityInfo
     */
    public EntityInfo getEntityInfo() {
        return entityInfo;
    }

    /**
     * @param entityInfo
     *            the entityInfo to set
     */
    public void setEntityInfo(final EntityInfo entityInfo) {
        this.entityInfo = entityInfo;
    }

    /**
     * @return the updateType
     */
    public RequestType getRequestType() {
        return requestType;
    }

    /**
     * @param updateType
     *            the updateType to set
     */
    public void setRequestType(final RequestType updateType) {
        this.requestType = updateType;
    }

    /**
     * @return the generatedCertificate
     */
    public Certificate getGeneratedCertificate() {
        return generatedCertificate;
    }

    /**
     * @param generatedCertificate
     *            the generatedCertificate to set
     */
    public void setGeneratedCertificate(final Certificate generatedCertificate) {
        this.generatedCertificate = generatedCertificate;
    }

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
     * @return the subjectUniqueIdentifierValue
     */
    public String getSubjectUniqueIdentifierValue() {
        return subjectUniqueIdentifierValue;
    }

    /**
     * @param subjectUniqueIdentifierValue
     *            the subjectUniqueIdentifierValue to set
     */
    public void setSubjectUniqueIdentifierValue(final String subjectUniqueIdentifierValue) {
        this.subjectUniqueIdentifierValue = subjectUniqueIdentifierValue;
    }

    /**
     * @return the issuerUniqueIdentifierValue
     */
    public String getIssuerUniqueIdentifierValue() {
        return issuerUniqueIdentifierValue;
    }

    /**
     * @param issuerUniqueIdentifierValue
     *            the issuerUniqueIdentifierValue to set
     */
    public void setIssuerUniqueIdentifierValue(final String issuerUniqueIdentifierValue) {
        this.issuerUniqueIdentifierValue = issuerUniqueIdentifierValue;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CertificateGenerationInfo [" + (null != version ? "version=" + version + ", " : "") + (null != validity ? "validity=" + validity + ", " : "") + "subjectUniqueIdentifier="
                + subjectUniqueIdentifier + ", issuerUniqueIdentifier=" + issuerUniqueIdentifier + ", forExternalCA=" + forExternalCA + ", "
                + (null != skewCertificateTime ? "skewCertificateTime=" + skewCertificateTime + ", " : "")
                + (null != keyGenerationAlgorithm ? "keyGenerationAlgorithm=" + keyGenerationAlgorithm + ", " : "")
                + (null != signatureAlgorithm ? "signatureAlgorithm=" + signatureAlgorithm + ", " : "")
                + (null != issuerSignatureAlgorithm ? "issuerSignatureAlgorithm=" + issuerSignatureAlgorithm + ", " : "")
                + (null != certificateExtensions ? "certificateExtensions=" + certificateExtensions + ", " : "")
                + (null != certificateRequest ? "certificateRequest=" + certificateRequest + ", " : "") + (issuerCA != null ? "issuerCA=" + issuerCA + ", " : "")
                + (null != cAEntityInfo ? "cAEntityInfo=" + cAEntityInfo + ", " : "") + (null != entityInfo ? "entityInfo=" + entityInfo + ", " : "")
                + (null != requestType ? "updateType=" + requestType : "") + (null != generatedCertificate ? "certificate=" + generatedCertificate : "")
                + (null != subjectUniqueIdentifierValue ? "subjectUniqueIdentifierValue=" + subjectUniqueIdentifierValue + ", " : "")
                + (null != issuerUniqueIdentifierValue ? "issuerUniqueIdentifierValue=" + issuerUniqueIdentifierValue + ", " : "") + "]";
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
        result = prime * result + ((cAEntityInfo == null) ? 0 : cAEntityInfo.hashCode());
        result = prime * result + ((certificateRequest == null) ? 0 : certificateRequest.hashCode());
        result = prime * result + ((certificateExtensions == null) ? 0 : certificateExtensions.hashCode());
        result = prime * result + ((entityInfo == null) ? 0 : entityInfo.hashCode());
        result = prime * result + ((issuerCA == null) ? 0 : issuerCA.hashCode());
        result = prime * result + (issuerUniqueIdentifier ? 1231 : 1237);
        result = prime * result + ((keyGenerationAlgorithm == null) ? 0 : keyGenerationAlgorithm.hashCode());
        result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
        result = prime * result + ((issuerSignatureAlgorithm == null) ? 0 : issuerSignatureAlgorithm.hashCode());
        result = prime * result + ((skewCertificateTime == null) ? 0 : skewCertificateTime.hashCode());
        result = prime * result + (subjectUniqueIdentifier ? 1231 : 1237);
        result = prime * result + ((requestType == null) ? 0 : requestType.hashCode());
        result = prime * result + ((validity == null) ? 0 : validity.hashCode());
        result = prime * result + ((version == null) ? 0 : version.hashCode());
        result = prime * result + ((generatedCertificate == null) ? 0 : generatedCertificate.hashCode());
        result = prime * result + (forExternalCA ? 1231 : 1237);
        result = prime * result + ((subjectUniqueIdentifierValue == null) ? 0 : subjectUniqueIdentifierValue.hashCode());
        result = prime * result + ((issuerUniqueIdentifierValue == null) ? 0 : issuerUniqueIdentifierValue.hashCode());
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
        final CertificateGenerationInfo other = (CertificateGenerationInfo) obj;
        if (cAEntityInfo == null) {
            if (other.cAEntityInfo != null) {
                return false;
            }
        } else if (!cAEntityInfo.equals(other.cAEntityInfo)) {
            return false;
        }
        if (certificateRequest == null) {
            if (other.certificateRequest != null) {
                return false;
            }
        } else if (!certificateRequest.equals(other.certificateRequest)) {
            return false;
        }
        if (certificateExtensions == null) {
            if (other.certificateExtensions != null) {
                return false;
            }
        } else if (!certificateExtensions.equals(other.certificateExtensions)) {
            return false;
        }
        if (entityInfo == null) {
            if (other.entityInfo != null) {
                return false;
            }
        } else if (!entityInfo.equals(other.entityInfo)) {
            return false;
        }
        if (issuerCA == null) {
            if (other.issuerCA != null) {
                return false;
            }
        } else if (!issuerCA.equals(other.issuerCA)) {
            return false;
        }
        if (issuerUniqueIdentifier != other.issuerUniqueIdentifier) {
            return false;
        }
        if (keyGenerationAlgorithm == null) {
            if (other.keyGenerationAlgorithm != null) {
                return false;
            }
        } else if (!keyGenerationAlgorithm.equals(other.keyGenerationAlgorithm)) {
            return false;
        }
        if (signatureAlgorithm == null) {
            if (other.signatureAlgorithm != null) {
                return false;
            }
        } else if (!signatureAlgorithm.equals(other.signatureAlgorithm)) {
            return false;
        }
        if (issuerSignatureAlgorithm == null) {
            if (other.issuerSignatureAlgorithm != null) {
                return false;
            }
        } else if (!issuerSignatureAlgorithm.equals(other.issuerSignatureAlgorithm)) {
            return false;
        }
        if (skewCertificateTime == null) {
            if (other.skewCertificateTime != null) {
                return false;
            }
        } else if (!skewCertificateTime.equals(other.skewCertificateTime)) {
            return false;
        }
        if (subjectUniqueIdentifier != other.subjectUniqueIdentifier) {
            return false;
        }
        if (requestType != other.requestType) {
            return false;
        }
        if (validity == null) {
            if (other.validity != null) {
                return false;
            }
        } else if (!validity.equals(other.validity)) {
            return false;
        }
        if (generatedCertificate == null) {
            if (other.generatedCertificate != null) {
                return false;
            }
        } else if (!generatedCertificate.equals(other.generatedCertificate)) {
            return false;
        }
        if (version != other.version) {
            return false;
        }
        if (forExternalCA != other.forExternalCA) {
            return false;
        }
        if (subjectUniqueIdentifierValue != other.subjectUniqueIdentifierValue) {
            return false;
        }
        if (issuerUniqueIdentifierValue != other.issuerUniqueIdentifierValue) {
            return false;
        }
        return true;
    }
}
