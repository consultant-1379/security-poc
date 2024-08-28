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
package com.ericsson.oss.itpf.security.credentialmanager.cli.implementation;

import java.io.PrintWriter;
import java.util.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaExternalServiceApiWrapperFactory;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.*;
import com.ericsson.oss.itpf.security.credmsapi.api.model.*;

/**
 * CommandTest
 * 
 * execute the "-t" option to call credentialmanagerAPI methods
 * 
 * parameter: a string with <command>=<param1>,<param2>..... (example -t getEntityByCategory=SERVICE)
 * 
 * @author enmadmin
 * 
 */
public class CommandTest implements Command {

    private CredMaExternalServiceApiWrapper extServiceApi = null;

    /**
         * 
         */
    // TORF-562254 update log4j
    private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

    private final Properties prop = PropertiesReader.getProperties(PropertiesReader.getConfigProperties().getProperty("commands"));
    private final Properties configProperties = PropertiesReader.getConfigProperties();
    private String arguments = "";
    private String myOTP = "";

    /**
     * @param arguments
     */
    public CommandTest() {
        this.extServiceApi = new CredMaExternalServiceApiWrapperFactory().getInstance(this.configProperties.getProperty("servicemanager.implementation"));
        this.myOTP = PropertiesReader.getConfigProperties().getProperty("testOtp");
    }

    /**
     * @return the arguments
     */
    //public String getArguments() {
    //    return arguments;
    //}

    /**
     * @param arguments
     *            the arguments to set
     */
    public void setArguments(final String arguments) {
        this.arguments = arguments;
    }

    @Override
    public int execute() {

        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_START_COMMAND), this.getType());
        LOG.info(this.arguments);
        final PrintWriter printWriter = new PrintWriter(System.out);
        printWriter.println("TEST MODE : args = " + this.arguments);

        // extract the command
        String[] args = null;
        args = this.arguments.split("=", 2);
        final String command = args[0];

        // extract the parameters
        final String[] params = args[1].split("\\+");

        //DEBUG
        printWriter.println("command=" + args[0]);
        printWriter.println("param size=" + params.length);
        for (int i = 0; i < params.length; i++) {
            printWriter.println("param " + i + ":" + params[i]);
        }
        printWriter.flush();

        //
        // getEntityByCategory
        //
        if ("getEntityByCategory".equals(command)) {
            printWriter.println("EXEC = " + command + "( " + params[0] + " )");

            List<EntitySummary> entities = new ArrayList<EntitySummary>();
            try {
                entities = this.extServiceApi.getEndEntitiesByCategory(params[0]);
            } catch (final GetEndEntitiesByCategoryException e) {
                // TODO Auto-generated catch block
                //e.printStackTrace();
                printWriter.println(" -->  GetEndEntitiesByCategoryException:" + e.getMessage());
            } catch (final InvalidCategoryNameException e) {
                // TODO Auto-generated catch block
                //e.printStackTrace();
                printWriter.println(" -->  InvalidCategoryNameException:" + e.getMessage());
            }
            if (entities.isEmpty()) {
                printWriter.println("No Entity");
            } else {
                for (int index = 0; index < entities.size(); index++) {
                    final String name = entities.get(index).getName();
                    final String state = entities.get(index).getStatus().toString();
                    printWriter.println("Entity n." + index + " = " + name + ", state = " + state);
                }
            }

        }

        //
        // Boolean issueCertificate(EntityInfo entityInfo, KeystoreInfo ksInfo) throws IssueCertificateException;
        //
        // EntityInfo == its name
        // final KeystoreInfo ksInfo = new KeystoreInfo("keyAndCertLocation", null, null, null, CertificateFormat.JKS, "", "alias");
        // arguments:
        // String entityName
        // String keystorePath
        // String Password
        // String alias
        // String keyStore format
        if ("issueCertificateForENIS".equals(command)) {
            printWriter.println("EXEC = " + command + "( " + params[0] + ", " + params[1] + ", " + params[2] + ", " + params[3] + ", " + params[4] + " )");

            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setEntityName(params[0]);
            entityInfo.setOneTimePassword(this.myOTP);
            
            final CertificateFormat certFormat = convertCertFormat(params[4]);
            final KeystoreInfo ksInfo = new KeystoreInfo(params[1], null, null, null, certFormat, params[2], params[3]);
            try {
                final Boolean result = this.extServiceApi.issueCertificateForENIS(entityInfo, ksInfo);
                printWriter.println("Result = " + result.toString());
            } catch (final IssueCertificateException e) {
                printWriter.println(" -->  IssueCertificateException:" + e.getMessage());
            } catch (final EntityNotFoundException e) {
                printWriter.println(" -->  EntityNotFoundException:" + e.getMessage());
            } catch (final InvalidCertificateFormatException e) {
                printWriter.println(" -->  InvalidCertificateFormatException:" + e.getMessage());
            } catch (final OtpNotValidException e) {
                printWriter.println(" -->  One Time Password Not Valid:" + e.getMessage());
            } catch (final OtpExpiredException e) {
                printWriter.println(" -->  One Time Password Expired:" + e.getMessage());
            }
        }

        //
        // Boolean reIssueCertificate(final EntityInfo entityInfo, final KeystoreInfo ksInfo, final CrlReason revocationReason) throws ReissueCertificateException   
        // Arguments:
        // String entityName
        // String keystorePath
        // String Password 
        // String alias
        // String keyStore format
        // String revocationReason 
        if ("reIssueCertificate".equals(command)) {

            printWriter.println("EXEC = " + command + "( " + params[0] + ", " + params[1] + ", " + params[2] + ", " + params[3] + ", " + params[4] + ", " + params[5] + ")");

            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setEntityName(params[0]);
            entityInfo.setOneTimePassword(this.myOTP);
            
            final CertificateFormat certFormat = convertCertFormat(params[4]);

            final KeystoreInfo ksInfo = new KeystoreInfo(params[1], null, null, null, certFormat, params[2], params[3]);

            final CrlReason crlReason = convertCrlReason(params[5]);

            try {
                final Boolean result = this.extServiceApi.reIssueCertificate(entityInfo, ksInfo, crlReason);
                printWriter.println("Result = " + result.toString());
            } catch (final ReissueCertificateException e) {
                printWriter.println(" -->  reIssueCertificateException:" + e.getMessage());
            } catch (final EntityNotFoundException e) {
                printWriter.println(" -->  reIssueCertificate: EntityNotFoundException:" + e.getMessage());
            } catch (final InvalidCertificateFormatException e) {
                printWriter.println(" -->  reIssueCertificate: InvalidCertificateFormatException:" + e.getMessage());
            } catch (final OtpNotValidException e) {
                printWriter.println(" -->  reIssueCertificate: One Time Password Not Valid:" + e.getMessage());
            } catch (final OtpExpiredException e) {
                printWriter.println(" -->  reIssueCertificate: One Time Password Expired:" + e.getMessage());
            }
        }

        //   
        // Boolean revokeCertificate(final EntityInfo entityInfo, final CrlReason revocationReason) throws RevokeCertificateException 
        // Arguments:
        // String entityName
        // String revocationReason            
        if ("revokeCertificate".equals(command)) {

            printWriter.println("EXEC = " + command + "( " + params[0] + ", " + params[1] + ")");

            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setEntityName(params[0]);
            entityInfo.setOneTimePassword(this.myOTP);
            
            final CrlReason crlReason = convertCrlReason(params[1]);

            try {
                final Boolean result = this.extServiceApi.revokeCertificate(entityInfo, crlReason);
                printWriter.println("Result = " + result.toString());
            } catch (final RevokeCertificateException e) {
                printWriter.println(" -->  revokeCertificateException:" + e.getMessage());
            } catch (final EntityNotFoundException e) {
                printWriter.println(" -->  EntityNotFoundException:" + e.getMessage());
            }

        }

        //
        // Boolean public List<CertificateSummary> getCertificatesByEntityName(final String entityName, final EntityType entityType, final CertificateStatus... certificateStatus)
        // throws CertificateNotFoundException, GetCertificatesByEntityNameException, EntityNotFoundException
        // Arguments:
        // String entityName
        // String entityType
        // String certificateStatus1
        // String certificateStatus2 (optional)
        // String certificateStatus3 (optional)
        // String certificateStatus4 (optional)
        //
        if ("getCertificatesByEntityName".equals(command)) {
            final StringBuffer buff = new StringBuffer("");
            for (final String p : params) {
                buff.append(p + " ");
            }

            printWriter.println("EXEC = " + command + "( " + buff.toString() + ")");
            printWriter.flush();

            final String entityName = params[0];

            final EntityType entityType = EntityType.fromValue(params[1]);

            final CertificateStatus[] certStatusArray = new CertificateStatus[params.length - 2];
            for (int i = 2; i < params.length; i++) {
                certStatusArray[i - 2] = CertificateStatus.fromValue(params[i].toUpperCase());
            }

            List<CertificateSummary> result = new ArrayList<CertificateSummary>();
            try {
                result = this.extServiceApi.getCertificatesByEntityName(entityName, entityType, certStatusArray);
            } catch (final CertificateNotFoundException e) {
                printWriter.println(" -->  CertificateNotFoundException:" + e.getMessage());
                printWriter.flush();
            } catch (final EntityNotFoundException e) {
                printWriter.println(" -->  EntityNotFoundException:" + e.getMessage());
                printWriter.flush();
            } catch (final GetCertificatesByEntityNameException e) {
                printWriter.println(" -->  GetCertificatesByEntityNameException:" + e.getMessage());
                printWriter.flush();
            }

            for (final CertificateSummary certSummary : result) {
                printWriter.println("certificate Summary : issuerDN = " + certSummary.getIssuerDN() + " subjectDN = " + certSummary.getSubjectDN() + " certificateSN = "
                        + certSummary.getCertificateSN() + " certificateStatus = " + certSummary.getCertificateStatus().toString());
            }
            printWriter.flush();
        }

        //
        // Boolean revokeEntityCertificate(String issuerDN, String subjectDN, String certificateSN, CrlReason revocationReason) throws CertificateNotFoundException, ExpiredCertificateException,
        // AlreadyRevokedCertificateException, RevokeEntityCertificateException
        // Arguments:
        // String issuerDN 
        // String subjectDN 
        // String certificateSN 
        // CrlReason revocationReason
        //
        if ("revokeEntityCertificate".equals(command)) {

            printWriter.println("EXEC = " + command + " ( ISSUER = " + params[0] + ",  SUBJECT = " + params[1] + ",  SN = " + params[2] + ",  revocReason = " + params[3] + " )");
            printWriter.flush();

            final CrlReason crlReason = convertCrlReason(params[3]);

            try {
                final Boolean result = this.extServiceApi.revokeEntityCertificate(params[0], params[1], params[2], crlReason);
                printWriter.println("Result = " + result.toString());
                printWriter.flush();
            } catch (final CertificateNotFoundException e) {
                printWriter.println(" -->  CertificateNotFoundException:" + e.getMessage());
                printWriter.flush();
            } catch (final ExpiredCertificateException e) {
                printWriter.println(" -->  ExpiredCertificateException:" + e.getMessage());
                printWriter.flush();
            } catch (final AlreadyRevokedCertificateException e) {
                printWriter.println(" -->  AlreadyRevokedCertificateException:" + e.getMessage());
                printWriter.flush();
            } catch (final RevokeEntityCertificateException e) {
                printWriter.println(" -->   RevokeEntityCertificateException:" + e.getMessage());
                printWriter.flush();
            }

        }

        //
        // Boolean reIssueCertificate(final EntityInfo entityInfo, final KeystoreInfo ksInfo, final CrlReason revocationReason) throws ReissueCertificateException   
        // Arguments:
        // String entityName
        // String keystorePath
        // String passwordLocation
        // String revocationReason 
        if ("reIssueLegacyXMLCertificate".equals(command)) {

            printWriter.println("EXEC = " + command + "( " + params[0] + ", " + params[1] + ", " + params[2] + ", " + params[3] + ")");

            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setEntityName(params[0]);
            entityInfo.setOneTimePassword(this.myOTP);
            
            try {
                final Boolean result = this.extServiceApi.reIssueLegacyXMLCertificate(entityInfo, params[1], true, params[2], convertCrlReason(params[3]));
                printWriter.println("Result = " + result.toString());
            } catch (final EntityNotFoundException e) {
                printWriter.println(" -->  EntityNotFoundException:" + e.getMessage());
            } catch (final OtpNotValidException e) {
                printWriter.println(" -->  One Time Password Not Valid:" + e.getMessage());
            } catch (final OtpExpiredException e) {
                printWriter.println(" -->  One Time Password Expired:" + e.getMessage());
            } catch (final ReIssueLegacyXMLCertificateException e) {
                printWriter.println(" -->  reIssueCertificateException:" + e.getMessage());
            }
        }

        printWriter.flush();
        printWriter.close();
        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_END_COMMAND), this.getType());
        return 0;

    }

    @Override
    public COMMAND_TYPE getType() {
        return COMMAND_TYPE.TEST;
    }

    @Override
    public List<String> getValidArguments() {
        final List<String> list = new ArrayList<String>();
        for (final String vArg : this.prop.getProperty("command.test.valideArguments").split(",")) {
            list.add(vArg);
        }
        return list;
    }

    /**
     * @param args
     * @return
     */
    private static CertificateFormat convertCertFormat(final String certFormatString) {
        CertificateFormat certFormat = null;
        switch (certFormatString.toUpperCase()) {
        case ("JKS"):
            certFormat = CertificateFormat.JKS;
            break;
        case ("PKCS12"):
            certFormat = CertificateFormat.PKCS12;
            break;
        case ("JCEKS"):
            certFormat = CertificateFormat.JCEKS;
            break;
        case ("BASE_64"):
            certFormat = CertificateFormat.BASE_64;
            break;
        default:
            LOG.info("Certificate format not specified!");
            break;
        }
        return certFormat;
    }

    /**
     * @param args
     * @return
     */
    private static CrlReason convertCrlReason(final String crlReasonString) {
        CrlReason crlReason = null;
        switch (crlReasonString.toUpperCase()) {
        case ("A_A_COMPROMISE"):
            crlReason = CrlReason.A_A_COMPROMISE;
            break;
        case ("AFFILIATION_CHANGED"):
            crlReason = CrlReason.AFFILIATION_CHANGED;
            break;
        case ("CA_COMPROMISE"):
            crlReason = CrlReason.CA_COMPROMISE;
            break;
        case ("CERTIFICATE_HOLD"):
            crlReason = CrlReason.CERTIFICATE_HOLD;
            break;
        case ("CESSATION_OF_OPERATION"):
            crlReason = CrlReason.CESSATION_OF_OPERATION;
            break;
        case ("KEY_COMPROMISE"):
            crlReason = CrlReason.KEY_COMPROMISE;
            break;
        case ("PRIVILEGE_WITHDRAWN"):
            crlReason = CrlReason.PRIVILEGE_WITHDRAWN;
            break;
        case ("REMOVE_FROM_CRL"):
            crlReason = CrlReason.REMOVE_FROM_CRL;
            break;
        case ("SUPERSEDED"):
            crlReason = CrlReason.SUPERSEDED;
            break;
        case ("UNSPECIFIED"):
            crlReason = CrlReason.UNSPECIFIED;
            break;
        default:
            LOG.info("Crl reason not specified!");
            break;
        }
        return crlReason;
    }
}
