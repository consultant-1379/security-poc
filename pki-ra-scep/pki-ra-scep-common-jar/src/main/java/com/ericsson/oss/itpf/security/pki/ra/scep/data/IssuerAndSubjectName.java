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
package com.ericsson.oss.itpf.security.pki.ra.scep.data;

import java.io.IOException;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;

/**
 * This class contains the issuerName and subjectName values of the requested Certificate.
 *
 * @author xtelsow
 */
public class IssuerAndSubjectName extends ASN1Object {

    private X500Name issuerName;

    private X500Name subjectName;

    public IssuerAndSubjectName() {
        super();
    }

    /**
     * This constructor is used to set the issuer and subject names from ASN1Sequence.
     *
     * @param seq
     *            is the ASN1Sequence from which the issue name and subject name will be retrieved.
     */
    private IssuerAndSubjectName(final ASN1Sequence seq) {
        this.issuerName = X500Name.getInstance(seq.getObjectAt(0));
        this.subjectName = X500Name.getInstance(seq.getObjectAt(1));
    }

    /**
     * This constructor is used to set the issuer and subject names.
     * 
     * @param issuerName
     *            issuerName is the X500Name issuer name of the requested Certificate.
     * @param subjectName
     *            subjectName is the X500Name subject name of the requested Certificate.
     */
    public IssuerAndSubjectName(final X500Name issuerName, final X500Name subjectName) {
        this.issuerName = issuerName;
        this.subjectName = subjectName;
    }

	/**
     * This method is used to get IssuerAndSubjectName object from byte array.
     * 
     * @param encoded
     *            byte array of IssuerAndSubjectName.
     * @return IssuerAndSubjectName is the IssuerAndSubjectName object which contains the issuer name and subject name.
     * @throws IOException
     *             is thrown while reading IssuerAndSubjectName from byte array.
     */
    @Profiled
    public static IssuerAndSubjectName getInstance(final byte[] encoded) throws IOException {
        final Object obj = ASN1Primitive.fromByteArray(encoded);
        if (obj instanceof IssuerAndSerialNumber) {
            return (IssuerAndSubjectName) obj;
        } else if (obj != null) {
            return new IssuerAndSubjectName(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    @Profiled
    public X500Name getIssuerName() {
        return issuerName;
    }

    public X500Name getSubjectName() {
        return subjectName;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public void setIssuerName(final X500Name issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @param subjectName
     *            the subjectName to set
     */
    public void setSubjectName(final X500Name subjectName) {
        this.subjectName = subjectName;
    }

    /**
     * This method adds the issuerName, subjectNames to the ASN1EncodableVector.
     *
     * 
     * @return ASN1Primitive is the ASN1Primitive of issuer name and subject name.
     */
    @Profiled
    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(issuerName);
        v.add(subjectName);

        return new DERSequence(v);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((issuerName == null) ? 0 : issuerName.hashCode());
        result = prime * result + ((subjectName == null) ? 0 : subjectName.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        IssuerAndSubjectName other = (IssuerAndSubjectName) obj;
        if (issuerName == null) {
            if (other.issuerName != null)
                return false;
        } else if (!issuerName.equals(other.issuerName))
             return false;
        if (subjectName == null) {
            if (other.subjectName != null)
                return false;
        } else if (!subjectName.equals(other.subjectName))
            return false;
        return true;
    }
}
