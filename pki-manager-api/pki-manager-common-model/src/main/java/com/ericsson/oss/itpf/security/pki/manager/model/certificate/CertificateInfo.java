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
package com.ericsson.oss.itpf.security.pki.manager.model.certificate;

import java.io.Serializable;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * This class contains all the major fields of a Certificate along with the entity name for which the certificate is issued.
 * 
 * <ul>
 * <li>id : id of the certificate.</li>
 * <li>Serial Number : Serial number of the certificate.</li>
 * <li>NotBefore : Time of the certificate generation.</li>
 * <li>NotAfter : Expire Time of the certificate.</li>
 * <li>Status : Status of the certificate whether it is active, revoked or expired.</li>
 * <li>Subject : Subject dn of the certificate.</li>
 * <li>SubjectAltName : SAN extension of the certificate.</li>
 * <li>EntityName : {@link Entity } .</li>
 * <li>isCAEntity : True for CAEntity / False for End Entity .</li>
 * </ul>
 * This is used to represent the certificate data and Entity
 * 
 */
public class CertificateInfo implements Serializable {

    private static final long serialVersionUID = -5594232074558608857L;

    private long id;

    private String serialNumber;

    private Date notBefore;

    private Date notAfter;

    private CertificateStatus status;

    private Subject subject;

    private SubjectAltName subjectAltName;

    private String entityName;

    private boolean isCAEntity;

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
     * @return the serialNumber
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the notBefore
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     * @param notBefore
     *            the notBefore to set
     */
    public void setNotBefore(final Date notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * @return the notAfter
     */
    public Date getNotAfter() {
        return notAfter;
    }

    /**
     * @param notAfter
     *            the notAfter to set
     */
    public void setNotAfter(final Date notAfter) {
        this.notAfter = notAfter;
    }

    /**
     * @return the status
     */
    public CertificateStatus getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final CertificateStatus status) {
        this.status = status;
    }

    /**
     * @return the subject
     */
    public Subject getSubject() {
        return subject;
    }

    /**
     * @param subject
     *            the subject to set
     */
    public void setSubject(final Subject subject) {
        this.subject = subject;
    }

    /**
     * @return the subjectAltName
     */
    public SubjectAltName getSubjectAltName() {
        return subjectAltName;
    }

    /**
     * @param subjectAltName
     *            the subjectAltName to set
     */
    public void setSubjectAltName(final SubjectAltName subjectAltName) {
        this.subjectAltName = subjectAltName;
    }

    /**
     * @return the entityName
     */
    public String getEntityName() {
        return entityName;
    }

    /**
     * @param entityName
     *            the entityName to set
     */
    public void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    /**
     * @return the isCAEntity
     */
    public boolean isCAEntity() {
        return isCAEntity;
    }

    /**
     * @param isCAEntity
     *            the isCAEntity to set
     */
    public void setCAEntity(boolean isCAEntity) {
        this.isCAEntity = isCAEntity;
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
        result = prime * result + ((notAfter == null) ? 0 : notAfter.hashCode());
        result = prime * result + ((notBefore == null) ? 0 : notBefore.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subject == null) ? 0 : subject.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((entityName == null) ? 0 : entityName.hashCode());
        result = prime * result + (isCAEntity ? 1231 : 1237);
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
        final CertificateInfo other = (CertificateInfo) obj;
        if (notAfter == null) {
            if (other.notAfter != null) {
                return false;
            }
        } else if (!notAfter.equals(other.notAfter)) {
            return false;
        }
        if (notBefore == null) {
            if (other.notBefore != null) {
                return false;
            }
        } else if (!notBefore.equals(other.notBefore)) {
            return false;
        }
        if (serialNumber == null) {
            if (other.serialNumber != null) {
                return false;
            }
        } else if (!serialNumber.equals(other.serialNumber)) {
            return false;
        }
        if (status != other.status) {
            return false;
        }
        if (subject == null) {
            if (other.subject != null) {
                return false;
            }
        } else if (!subject.equals(other.subject)) {
            return false;
        }
        if (subjectAltName == null) {
            if (other.subjectAltName != null) {
                return false;
            }
        } else if (!subjectAltName.equals(other.subjectAltName)) {
            return false;
        }
        if (entityName == null) {
            if (other.entityName != null) {
                return false;
            }
        } else if (!entityName.equals(other.entityName)) {
            return false;
        }
        if (isCAEntity != other.isCAEntity) {
            return false;
        }
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "Certificate [id=" + id + ", " + (null != serialNumber ? "serialNumber=" + serialNumber + ", " : "") + (null != notBefore ? "notBefore=" + notBefore + ", " : "")
                + (null != notAfter ? "notAfter=" + notAfter + ", " : "") + (null != status ? "status=" + status + ", " : "") + (null != subject ? "subject=" + subject + ", " : "")
                + (null != subjectAltName ? "subjectAltName=" + subjectAltName + ", " : "") + (null != entityName ? "entityName=" + entityName + ", " : "") + "isCAEntity=" + isCAEntity;
    }
}
