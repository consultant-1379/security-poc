/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * This class extends X500Name and implements Serializable so it can be used for remote calls.
 *
 * @author egbobcs
 */
public class CredentialManagerX500Name extends X500Name implements Externalizable {

    private static final long serialVersionUID = 816765026133699399L;

    private transient X500Name wrapped;

    /**
     * Constructs an object instance
     * 
     * @param name
     *            as an X509Name object
     */
    public CredentialManagerX500Name(final X500Name name) {
        super(name.toString());
        this.wrapped = new X500Name(name.toString());
    }

    /**
     * Constructs an object instance
     * 
     * @param name
     *            as String in X509 format (For example: "CN=Example")
     * 
     */
    public CredentialManagerX500Name(final String name) {
        super(name);
        this.wrapped = new X500Name(name.toString());
    }

    @Override
    public void readExternal(final ObjectInput in) throws IOException, ClassNotFoundException {
        final String name = in.readUTF();
        this.wrapped = new X500Name(name);
    }

    @Override
    public void writeExternal(final ObjectOutput out) throws IOException {
        out.writeUTF(toString());
    }

    //IMPLEMENTATION of ALL METHODS using the wrapped X500Name object

    //	@Override
    //	public String toString() {
    //		return this.wrapped.toString();
    //	}

    @Override
    public boolean equals(final Object arg0) {
        return this.wrapped.equals(arg0);
    }

    //	@SuppressWarnings("PMD")
    //	@Override
    //	public Vector getValues() {
    //		return this.wrapped.getValues();
    //	}
    //
    //	@SuppressWarnings("PMD")
    //	@Override
    //	public Vector getValues(final ASN1ObjectIdentifier arg0) {		
    //		return this.wrapped.getValues(arg0);
    //	}

    @Override
    public int hashCode() {
        return this.wrapped.hashCode();
    }

    public ASN1Primitive toASN1Object() {
        return this.wrapped.toASN1Primitive();
    }

    @Override
    public String toString() {
        return this.wrapped.toString();
    }

    public byte[] getDEREncoded() {
        try {
            return this.wrapped.getEncoded(ASN1Encoding.DER);
        } catch (final IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return this.wrapped.toASN1Primitive();
    }

    @Override
    public byte[] getEncoded() throws IOException {
        return this.wrapped.getEncoded();
    }

    @Override
    public byte[] getEncoded(final String arg0) throws IOException {
        return this.wrapped.getEncoded(arg0);
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
    }
}
