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
package com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity;

import java.io.Serializable;
import java.sql.Timestamp;

import javax.persistence.*;

import com.ericsson.oss.itpf.modeling.annotation.constraints.Size;

/**
 * This Entity Class is used to persist or retrieve the corresponding request and response values in database. Pkcs7ScepRequestEntity contains following fields.
 * <ul>
 * <li>transactionId is the primaryKey String attribute which holds the transactionId for ScepRequest</li>
 * <li>subjectDN is a string attribute which is the Subject Name of the requested Certificate</li>
 * <li>issuerDN is the string attribute which is the Issuer Name of the requested Certificate</li>
 * <li>messageTime is the Date attribute which is time when PKCSReq message has been processed by SCEP Service</li>
 * <li>failInfo is the string attribute which holds the failure reason for generating the ScepResponse</li>
 * <li>status is a integer attribute which holds the status of the certificate of the SCEP transaction</li>
 * <li>certificate is a byte array attribute which holds the certificate generated certificate</li>
 * </ul>
 *
 *
 * @author xkarlak
 */
@Entity
@Table(name = "ScepRequest")
@NamedQueries({
        @NamedQuery(name = "Pkcs7ScepRequestEntity.deleteEntity", query = "delete from Pkcs7ScepRequestEntity r where r.messageTime < :intervalTime")})
public class Pkcs7ScepRequestEntity implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -1005784109105924126L;

    public Pkcs7ScepRequestEntity() {
        super();
    }

    @Id
    @Column(unique = true, nullable = false, name = "transaction_id")
    @Size(max = 255)
    private String transactionId;

    @Column(nullable = false, name = "subject_dn")
    @Size(max = 255)
    private String subjectDN;

    @Column(nullable = false, name = "issuer_dn")
    @Size(max = 255)
    private String issuerDN;

    @Column(nullable = false, name = "message_time")
    private Timestamp messageTime;

    @Column(name = "fail_info")
    @Size(max = 255)
    private String failInfo;

    @Column(nullable = false, name = "status_id")
    @Size(max = 255)
    private int status;

    @Column(name = "certificate")
    private byte[] certificate;

    public Pkcs7ScepRequestEntity(final String transactionId, final String subjectDN, final String issuerDN, final Timestamp messageTime, final String failInfo, final int status,
            final byte[] certificate) {

        super();
        this.transactionId = transactionId;
        this.subjectDN = subjectDN;
        this.issuerDN = issuerDN;
        this.messageTime = messageTime;
        this.failInfo = failInfo;
        this.status = status;
        this.certificate = certificate;

    }

    /**
     * @return the transactionid
     */
    public String getTransactionId() {
        return transactionId;
    }

    /**
     * @param transactionid
     *            the transactionid to set
     */
    public void setTransactionid(final String transactionid) {
        this.transactionId = transactionid;
    }

    /**
     * @return the subjectname
     */
    public String getSubjectname() {
        return subjectDN;
    }

    /**
     * @param subjectname
     *            the subjectname to set
     */
    public void setSubjectname(final String subjectname) {
        this.subjectDN = subjectname;
    }

    /**
     * @return the issuername
     */
    public String getIssuername() {
        return issuerDN;
    }

    /**
     * @param issuername
     *            the issuername to set
     */
    public void setIssuername(final String issuerDN) {
        this.issuerDN = issuerDN;
    }

    /**
     * @return the messagetime
     */
    public Timestamp getMessageTime() {
        return messageTime;
    }

    /**
     * @param messagetime
     *            the messagetime to set
     */
    public void setMessageTime(final Timestamp messagetime) {
        this.messageTime = messagetime;
    }

    /**
     * @return the failinfo
     */
    public String getFailInfo() {
        return failInfo;
    }

    /**
     * @param failInfo
     *            the failinfo to set
     */
    public void setFailInfo(final String failInfo) {
        this.failInfo = failInfo;
    }

    /**
     * @return the status
     */
    public int getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final int status) {
        this.status = status;
    }

    /**
     * @return the certificate the client Request Certificate.
     */
    public byte[] getCertificate() {
        return certificate;
    }

    /**
     * @param certificate
     *            the certificate to set
     */
    public void setCertificate(final byte[] certificate) {
        this.certificate = certificate;
    }

}
