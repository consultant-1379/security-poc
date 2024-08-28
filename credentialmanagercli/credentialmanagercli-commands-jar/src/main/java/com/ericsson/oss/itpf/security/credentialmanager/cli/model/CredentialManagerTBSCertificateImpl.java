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
package com.ericsson.oss.itpf.security.credentialmanager.cli.model;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.utils.HostnameResolveUtil;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TBSCertificateType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCertificateExt;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerTBSCertificate;

/**
 * 
 * The class hold the information of TBSCertificate
 * 
 */
public class CredentialManagerTBSCertificateImpl implements CredentialManagerTBSCertificate {
    /**
     * 
     */
    private static final long serialVersionUID = -1602797081976741374L;
    //private BigInteger version;
    private String entityName;

    private String subjectDN;
    //private String issuerDN;
    private CredentialManagerCertificateExt certificateExtension;
    private final transient HostnameResolveUtil hru = new HostnameResolveUtil();

    public CredentialManagerTBSCertificateImpl(final Object tbs) {

        TBSCertificateType tbscertificate;

        if (tbs != null && tbs instanceof TBSCertificateType) {
            tbscertificate = (TBSCertificateType) tbs;
        } else {
            throw new CredentialManagerException("Loading information of XML TBS Certificate Type...[Failed]");
        }

        this.setCertificateExtension(new CredentialManagerCertificateExtImpl(tbscertificate.getCertificateextension()));

        // data moved form XML to Profile
        //setVersion(BigInteger.valueOf(3));
        //setIssuerDN("atclvm387");	

        if (!(tbscertificate.getSubject() == null)) {

            this.setEntityName(this.substituteHostname(tbscertificate.getSubject().getEntityname()));

            if (tbscertificate.getSubject().getDistinguishname() != null) {
                // check format of distinguishname
                String subjectDN = tbscertificate.getSubject().getDistinguishname().trim();
                // substitute ##HOSTNAME or the ldpa check will fail
                subjectDN = this.substituteHostname(subjectDN);
                LdapName subjectLdapName = null;
                try {
                    subjectLdapName = new LdapName(subjectDN);
                } catch (final InvalidNameException e) {
                    throw new CredentialManagerException("Invalid Format in Subject Distinguish Name from TBS Certificate ");
                }
                // if ok save the data
                this.setSubjectDN(subjectLdapName.toString());
            } else {
                this.setSubjectDN("CN=" + this.entityName);
            }
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTBSCertificate #getVersion()
     */
    //	@Override
    //	public BigInteger getVersion() {
    //		return version;
    //	}

    /**
     * @param version
     *            the version to set
     */
    //	private void setVersion(final BigInteger version) {
    //		this.version = version;
    //	}

    /**
     * @return the entityName
     */
    @Override
    public String getEntityName() {
        return entityName;
    }

    /**
     * @param entityName
     *            the entityName to set
     */
    private void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTBSCertificate #getSubjectDN()
     */
    @Override
    public String getSubjectDN() {
        return this.subjectDN;
    }

    /**
     * 
     * @param subject
     * @return
     */
    private String substituteHostname(final String subject) {

        return this.hru.checkHostName(subject);
    }

    /**
     * @param subjectDN
     *            the subjectDN to set
     */
    private void setSubjectDN(final String subjectDN) {

        this.subjectDN = subjectDN;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTBSCertificate #getIssuerDN()
     */
    //	@Override
    //	public String getIssuerDN() {
    //		return issuerDN;
    //	}

    /**
     * @param issuerDN
     *            the issuerDN to set
     */
    //	private void setIssuerDN(final String issuerDN) {
    //		this.issuerDN = issuerDN;
    //	}

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTBSCertificate #getCertificateExtension()
     */
    @Override
    public CredentialManagerCertificateExt getCertificateExtension() {
        return this.certificateExtension;
    }

    /**
     * @param certificateExtension
     *            the certificateExtension to set
     */
    private void setCertificateExtension(final CredentialManagerCertificateExt certificateExtension) {
        this.certificateExtension = certificateExtension;
    }

}
