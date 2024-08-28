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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.business;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaServiceApiWrapper;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCertificateExt;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerKeyStore;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerTrustStore;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.CheckResult;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.AlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetEndEntitiesByCategoryException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCategoryNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCertificateFormatException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReIssueLegacyXMLCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReissueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeEntityCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateSummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntitySummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;

public class CredMaServiceApiWrapperMock implements CredMaServiceApiWrapper, CredMaExternalServiceApiWrapper {

    // TORF-562254 update log4j
    private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

    //private final Properties configProperties = PropertiesReader.getConfigProperties();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api. CredMaServiceApiWrapper#manageCertificateAndTrust(java.lang.String, java.lang.String, java.lang.String, java.util.List,
     * java.util.List, com.ericsson.oss.itpf.security.credentialmanager.cli.service.api. CredMaCliCertificateExtension)
     */
    @Override
    public Boolean manageCertificateAndTrust(final String entityName, final String distinguishName, final CredentialManagerSubjectAltName subjectAltName, final String entityProfileName,
            final List<CredentialManagerKeyStore> keystoreInfoList, final List<CredentialManagerTrustStore> truststoreInfoList, final List<CredentialManagerTrustStore> crlstoreInfoList,
            final CredentialManagerCertificateExt certificateExtension, final boolean certificateChain, final boolean overWrite) throws CredentialManagerException {

        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_ISSUECERTIFICATE), "Call MOCK manageCertificateAndTrust");
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_ISSUECERTIFICATE_START), entityName);
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_ISSUECERTIFICATE_START), distinguishName);
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_ISSUECERTIFICATE_START), subjectAltName.getValue());
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_ISSUECERTIFICATE_START), entityProfileName);

        // MOCK !!!!!!!!!!!

        // loop inside the store info to search for file name and create them
        final Iterator<CredentialManagerKeyStore> keystoreIter = keystoreInfoList.iterator();
        while (keystoreIter.hasNext()) {
            final CredentialManagerKeyStore keystoreItem = keystoreIter.next();
            String dummyfilename = keystoreItem.getKeyStorelocation();
            if ((dummyfilename != null) && (dummyfilename != "")) {
                final File dummyStore = new File(dummyfilename);
                try {
                    dummyStore.createNewFile();
                    this.writeSomething(dummyStore, keystoreItem.getAlias());
                } catch (final IOException e) {
                    // Auto-generated catch block
                    e.printStackTrace();
                }
            }
            dummyfilename = keystoreItem.getPrivateKeyLocation();
            if ((dummyfilename != null) && (dummyfilename != "")) {
                final File dummyStore = new File(dummyfilename);
                try {
                    dummyStore.createNewFile();
                    this.writeSomething(dummyStore, keystoreItem.getAlias());
                } catch (final IOException e) {
                    // Auto-generated catch block
                    e.printStackTrace();
                }
            }
            dummyfilename = keystoreItem.getCertificateLocation();
            if ((dummyfilename != null) && (dummyfilename != "")) {
                final File dummyStore = new File(dummyfilename);
                try {
                    dummyStore.createNewFile();
                    this.writeSomething(dummyStore, keystoreItem.getAlias());
                } catch (final IOException e) {
                    // Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }

        // copy truststore info
        final Iterator<CredentialManagerTrustStore> truststoreIter = truststoreInfoList.iterator();
        while (truststoreIter.hasNext()) {
            final CredentialManagerTrustStore truststoreItem = truststoreIter.next();
            final String dummyfilename = truststoreItem.getLocation();
            if ((dummyfilename != null) && (dummyfilename != "")) {
                final File dummyStore = new File(dummyfilename);
                try {
                    dummyStore.createNewFile();
                    this.writeSomething(dummyStore, truststoreItem.getAlias());
                } catch (final IOException e) {
                    // Auto-generated catch block
                    e.printStackTrace();
                }
            }
            ;
        }

        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_ISSUECERTIFICATE_END));

        return true;
    }

    private void writeSomething(final File file, final String content) {
        FileWriter fw;
        try {
            fw = new FileWriter(file.getAbsoluteFile());
            final BufferedWriter bw = new BufferedWriter(fw);
            bw.write(content);
            bw.close();
        } catch (final IOException e) {
            // Auto-generated catch block
            e.printStackTrace();
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaServiceApiWrapper#manageMyOwnCertificate(java.lang.String,
     * com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerSubjectAltName, java.lang.String, java.util.List,
     * com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCertificateExt)
     */
    @Override
    public Boolean manageCredMaCertificate(final String entityName, final String distinguishName, final CredentialManagerSubjectAltName subjectAltName, final String entityProfileName,
            final List<CredentialManagerKeyStore> keystoreInfoList, final List<CredentialManagerTrustStore> truststreInfoList, final List<CredentialManagerTrustStore> crlstoreInfoList,
            final CredentialManagerCertificateExt certificateExtension, final boolean overWrite, final boolean noLoop, final boolean isCheck, final boolean firstDayRun)
            throws CredentialManagerException {

        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CLICERTIFICATE), "Call MOCK manageMyOwnCertificate");
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICERTIFICATE), entityName);
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICERTIFICATE), distinguishName);
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICERTIFICATE), entityProfileName);

        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaServiceApiWrapper#manageCheck(java.lang.String, java.lang.String,
     * com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerSubjectAltName, java.lang.String, java.util.List, java.util.List, java.util.List,
     * com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCertificateExt, boolean)
     */
    @Override
    public CheckResult manageCheck(final String entityName, final String distinguishName, final CredentialManagerSubjectAltName subjectAltName, final String entityProfileName,
            final List<CredentialManagerKeyStore> keyStores, final List<CredentialManagerTrustStore> trustStores, final List<CredentialManagerTrustStore> crlStores,
            final CredentialManagerCertificateExt certificateExtensionInfo, final boolean certificateChain, final boolean firstDailyRun) {

        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CLICHECK), "Call MOCK manageCheck");
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICHECK), entityName);
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICHECK), distinguishName);
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICHECK), subjectAltName.getValue());
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICHECK), entityProfileName);
        final CheckResult result = new CheckResult();
        result.setResult("certificateUpdate", true);
        result.setResult("trustUpdate", true);
        result.setResult("crlUpdate", true);
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaServiceApiWrapper#getEndEntitiesByCategory(java.lang.String)
     */
    @Override
    public List<EntitySummary> getEndEntitiesByCategory(final String category) throws GetEndEntitiesByCategoryException, InvalidCategoryNameException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaServiceApiWrapper#issueCertificateForENIS(com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo,
     * com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo)
     */
    @Override
    public Boolean issueCertificateForENIS(final EntityInfo entityInfo, final KeystoreInfo ksInfo) throws IssueCertificateException, EntityNotFoundException, InvalidCertificateFormatException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper#reIssueCertificate(com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo,
     * com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)
     */
    @Override
    public Boolean reIssueCertificate(final EntityInfo entityInfo, final KeystoreInfo ksInfo, final CrlReason revocationReason) throws ReissueCertificateException, EntityNotFoundException,
            InvalidCertificateFormatException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper#revokeCertificate(com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo,
     * com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)
     */
    @Override
    public Boolean revokeCertificate(final EntityInfo entityInfo, final CrlReason revocationReason) throws RevokeCertificateException, EntityNotFoundException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaServiceApiWrapper#manageCheckTrustAndCRL(java.lang.String, java.util.List, java.util.List)
     */
    @Override
    public CheckResult manageCheckTrustAndCRL(final String trustProfileName, final List<CredentialManagerTrustStore> truststoreInfoList, final List<CredentialManagerTrustStore> crlstoreInfoList)
            throws CredentialManagerException {
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICHECK), trustProfileName);
        final CheckResult result = new CheckResult();
        result.setResult("certificateUpdate", true);
        result.setResult("trustUpdate", true);
        result.setResult("crlUpdate", true);
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper#getCredentialManagerInterfaceVersion()
     */
    @Override
    public String getCredentialManagerInterfaceVersion() {
        // TODO Auto-generated method stub
        return "mock";
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper#getCertificatesByEntityName(java.lang.String,
     * com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType, com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus[])
     */
    @Override
    public List<CertificateSummary> getCertificatesByEntityName(final String entityName, final EntityType entityType, final CertificateStatus... certificateStatus)
            throws CertificateNotFoundException, GetCertificatesByEntityNameException, EntityNotFoundException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper#revokeEntityCertificate(java.lang.String, java.lang.String, java.lang.String,
     * com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)
     */
    @Override
    public Boolean revokeEntityCertificate(final String issuerDN, final String subjectDN, final String certificateSN, final CrlReason revocationReason) throws CertificateNotFoundException,
            ExpiredCertificateException, AlreadyRevokedCertificateException, RevokeEntityCertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper#reIssueLegacyXMLCertificate(com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo,
     * java.lang.String, java.lang.Boolean, java.lang.String, com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)
     */
    @Override
    public Boolean reIssueLegacyXMLCertificate(EntityInfo entityInfo, String certificateLocation, Boolean certificateChain, String passwordLocation, CrlReason revocationReason)
            throws ReIssueLegacyXMLCertificateException, EntityNotFoundException, OtpNotValidException, OtpExpiredException {
        // TODO Auto-generated method stub
        return null;
    }

}
