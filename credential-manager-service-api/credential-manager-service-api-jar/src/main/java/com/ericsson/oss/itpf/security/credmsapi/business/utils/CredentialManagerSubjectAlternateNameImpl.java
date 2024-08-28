/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import java.io.IOException;
import java.util.*;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;

/**
 * 
 * @author ewagdeb
 * 
 */
public class CredentialManagerSubjectAlternateNameImpl implements CredentialManagerSubjectAlternateName {

    private static final Logger LOG = LogManager.getLogger(CredentialManagerSubjectAlternateNameImpl.class);

    /**
     *
     */
    private static final long serialVersionUID = 2542249818035074039L;
    private ALTERNATE_NAME_TYPE type;
    private List<String> value;
    private final Map<ALTERNATE_NAME_TYPE, List<String>> attributeNames = new HashMap<ALTERNATE_NAME_TYPE, List<String>>();
    private Attribute attribute;
    private String subjectAlternativeName = "";

    public CredentialManagerSubjectAlternateNameImpl(final Object subjectAlternateNameObj) {
        SubjectAlternativeNameType subjectAltName = null;

        if (subjectAlternateNameObj != null && subjectAlternateNameObj instanceof SubjectAlternativeNameType) {
            subjectAltName = (SubjectAlternativeNameType) subjectAlternateNameObj;

            if (!subjectAltName.getDirectoryname().isEmpty()) {

                this.attributeNames.put(ALTERNATE_NAME_TYPE.DIRECTORY_NAME, subjectAltName.getDirectoryname());

            }

            if (!subjectAltName.getDns().isEmpty()) {

                this.attributeNames.put(ALTERNATE_NAME_TYPE.DNS, subjectAltName.getDns());

            }

            if (!subjectAltName.getEmail().isEmpty()) {

                this.attributeNames.put(ALTERNATE_NAME_TYPE.EMAIL, subjectAltName.getEmail());

            }

            if (!subjectAltName.getIpaddress().isEmpty()) {

                this.attributeNames.put(ALTERNATE_NAME_TYPE.IP_ADDRESS, subjectAltName.getIpaddress());

            }

            if (!subjectAltName.getRegisteredid().isEmpty()) {

                this.attributeNames.put(ALTERNATE_NAME_TYPE.REGISTERED_ID, subjectAltName.getRegisteredid());

            }

            if (!subjectAltName.getUri().isEmpty()) {

                this.attributeNames.put(ALTERNATE_NAME_TYPE.URI, subjectAltName.getUri());

            }

            if (!subjectAltName.getOthername().isEmpty()) {

                this.attributeNames.put(ALTERNATE_NAME_TYPE.OTHER_NAME, subjectAltName.getOthername());

            }
            this.generateAttribute();

        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.pki.model. CredentialManagerSubjectAlternateName#getType()
     */
    @Override
    public ALTERNATE_NAME_TYPE getType() {
        return this.type;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.pki.model. CredentialManagerSubjectAlternateName
     * #setType(com.ericsson.oss.itpf.security .cli.pki.model.CredentialManagerSubjectAlternateNameBean .ALTERNATE_NAME_TYPE)
     */
    @Override
    public void setType(final ALTERNATE_NAME_TYPE type) {
        this.type = type;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.pki.model. CredentialManagerSubjectAlternateName#getValue()
     */
    @Override
    public List<String> getValue() {
        return this.value;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.pki.model. CredentialManagerSubjectAlternateName#setValue(java.util.List)
     */
    @Override
    public void setValue(final List<String> value) {
        this.value = value;
    }

    @Override
    public Attribute getAttribute() {

        return this.attribute;
    }

    private void generateAttribute() {

        final Vector<ASN1ObjectIdentifier> oids = new Vector<ASN1ObjectIdentifier>();
        oids.add(Extension.subjectAlternativeName);
        final Vector<GeneralName> entries = new Vector<GeneralName>();

        for (final ALTERNATE_NAME_TYPE type : this.attributeNames.keySet()) {

            final List<String> values = this.attributeNames.get(type);

            if (type.equals(ALTERNATE_NAME_TYPE.DIRECTORY_NAME)) {
                for (final String val : values) {

                    if (val != null && !val.equals("")) {
                        this.subjectAlternativeName += "directoryName=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.directoryName, val);
                        entries.add(subjectAltName);
                    }
                }
            }
            if (type.equals(ALTERNATE_NAME_TYPE.DNS)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        this.subjectAlternativeName += "dNSName=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.dNSName, val);
                        entries.add(subjectAltName);
                    }
                }
            }
            if (type.equals(ALTERNATE_NAME_TYPE.EMAIL)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        this.subjectAlternativeName += "rfc822Name=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.rfc822Name, val);
                        entries.add(subjectAltName);
                    }
                }
            }
            if (type.equals(ALTERNATE_NAME_TYPE.URI)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        this.subjectAlternativeName += "uniformResourceIdentifier=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.uniformResourceIdentifier, val);
                        entries.add((subjectAltName));
                    }
                }
            }
            if (type.equals(ALTERNATE_NAME_TYPE.IP_ADDRESS)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        this.subjectAlternativeName += "iPAddress=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.iPAddress, val);
                        entries.add((subjectAltName));
                    }
                }
            }
            if (type.equals(ALTERNATE_NAME_TYPE.OTHER_NAME)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        this.subjectAlternativeName += "otherName=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.otherName, val);//Bug: OtherName needs a ASN1Encodable not a String
                        entries.add((subjectAltName));
                    }
                }
            }
            if (type.equals(ALTERNATE_NAME_TYPE.REGISTERED_ID)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        this.subjectAlternativeName += "registeredID=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.registeredID, val);
                        entries.add((subjectAltName));
                    }
                }
            }
        }

        final GeneralName[] names = new GeneralName[entries.size()];
        entries.copyInto(names);

        final GeneralNames generalNames = new GeneralNames(names);

        final ExtensionsGenerator extGen = new ExtensionsGenerator();

        try {
            extGen.addExtension(Extension.subjectAlternativeName, false, generalNames);
        } catch (final IOException e) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_UTILS_ADD_CERTEXTENSION);
            //e.printStackTrace();
        }

        final Extensions extensions = extGen.generate();
        this.attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));
    }

    @Override
    public String getSubjectAlternativeName() {
        if (this.subjectAlternativeName.endsWith(",")) {
            this.subjectAlternativeName = this.subjectAlternativeName.substring(0, this.subjectAlternativeName.length() - 1);
        }
        return this.subjectAlternativeName;
    }
}
