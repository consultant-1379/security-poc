/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc_ The programs may be used and/or copied only with written
 * permission from Ericsson Inc_ or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied_
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

public final class ErrorMsg {

    /**
     * notices a malformed IP address
     * 
     * @param IP
     *            Address
     */
    public final static String API_ERROR_SERVICE_ADDRESS_FORMAT = "Parsing {} [Failed]";

    /**
     * notices a failed http method invoking
     * 
     * @param Request
     * @param IP
     *            Address
     */
    public final static String API_ERROR_SERVICE_HTTP_INVOKE = "Invoking http method {} on host {} [Failed]";

    /**
     * notices a failed CSR conversion in http request
     */
    public final static String API_ERROR_SERVICE_GET_CSR = "Converting to string certificate signing request in http request [Failed]";

    /**
     * notices a failed certificate conversion in http response
     */
    public final static String API_ERROR_SERVICE_GET_CERT = "Converting to CredentialManagerX509Certificate certificate in http response [Failed]";

    /**
     * notices a failed trust store insertion in ObjectInputStream
     * 
     * @param Trust
     *            Chain entry value
     */
    public final static String API_ERROR_SERVICE_GET_TRUSTENTRY = "Inserting in ObjectInputStream trust store entry {} [Failed]";

    /**
     * notices a missed CA in the trust chain
     */
    public final static String API_ERROR_SERVICE_GET_CA = "Getting CA from trust chain [Failed]";

    /**
     * notices a failed json parsing for marshalling
     */
    public final static String API_ERROR_SERVICE_JMARSHAL_PROCESSING = "Parsing Json for marshalling [Failed]";

    /**
     * notices an unsupported json encoding for marshalling
     */
    public final static String API_ERROR_SERVICE_JMARSHAL_ENCODING = "Unsupported json object encoding";

    /**
     * notices a failed JNDI resolving for Credential Manager
     * 
     * @param Lookup
     *            Name
     */
    public final static String API_ERROR_SERVICE_JNDI_RESOLVE = "Resolving JNDI name for Credential Manager given {} [Failed]";

    /**
     * notices a failed JNDI resolving for Credential Manager
     * 
     * @param Lookup
     *            Name
     */
    public final static String API_ERROR_SERVICE_JNDI_RESOLVE_VERSION = "Resolving JNDI name for Credential Manager given {} for version {} [Failed]";

    /**
     * notices a malformed REST address
     */
    public final static String API_ERROR_SERVICE_PARSE_RESTADDRESSES = "Parsing REST addresses [Failed]";

    /**
     * notices a exception during Thread.sleep
     */
    public final static String API_ERROR_SERVICE_SLEEP = "Error during sleep";

    /**
     * notices an invalid method calling by REST service mode
     */
    public final static String API_ERROR_SERVICE_REST_INVALID_METHOD = "Invalid method calling by REST mode";

    /**
     * notices an invalid method calling by SECURE service mode
     */
    public final static String API_ERROR_SERVICE_SECURE_INVALID_METHOD = "Invalid method calling by SECURE mode";

    /**
     * notices a missed entity
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_SERVICE_GET_ENTITY = "Getting entity {} [Failed]";

    /**
     * notices a missed certificate
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_SERVICE_GET_CERTIFICATE = "Getting certificate for {} [Failed]";
    
    /**
     * notices an invalid otp
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_SERVICE_INVALID_OTP = "Invalid otp for {} [Failed]";
    
    /**
     * notices an expired otp
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_SERVICE_EXPIRED_OTP = "Expired otp for {} [Failed]";

    /**
     * notices missed trust certificates
     * 
     * @param Entity
     *            Profile Name
     * @param Exception
     *            Exception Name
     */
    public final static String API_ERROR_SERVICE_GET_TRUSTCERTS = "Getting trust certificates for {} [Failed], cause {}";

    /**
     * notices a missed CRL
     * 
     * @param Entity
     *            Profile Name
     */
    public final static String API_ERROR_SERVICE_GET_CRL = "Getting CRL for {} [Failed]";

    /**
     * notices a failure loading Credential Manager properties
     */
    public final static String API_ERROR_SERVICE_LOAD_CMPROPERTIES = "Loading Credential Manager properties [Not Found]";

    /**
     * notices a failed key pair creation
     * 
     * @param Entity
     *            DN
     */
    public final static String API_ERROR_BUSINESS_CREATE_KEYPAIR = "Creating key pair for {} [Failed]";

    /**
     * notices a missed key pair
     */
    public final static String API_ERROR_BUSINESS_GET_KEYPAIR = "Getting CSR key pair [Null]";

    /**
     * notices a failed CSR creation
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CREATE_CSR = "Creating CSR for {} [Failed]";

    /**
     * notices a missed CSR
     */
    public final static String API_ERROR_BUSINESS_GET_CSR = "Getting CSR[Null]";

    /**
     * notices a failed certificate encoding
     */
    public final static String API_ERROR_BUSINESS_ENCODE_CERT = "CertHandler encoding certificate [Failed]";

    /**
     * notices a missed CSR using REST
     */
    public final static String API_ERROR_BUSINESS_GET_RESTCSR = "Getting CSR with REST [Null]";

    /**
     * notices a missed certificate handler
     */
    public final static String API_ERROR_BUSINESS_GET_CERTHANDLER = "Getting certificate handler [Null]";

    /**
     * notices certificate multiple locations
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CERTIFICATE_MULTIPLELOC = "Multiple locations for {} certificate";

    /**
     * notices certificate missing location
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CERTIFICATE_MISSINGLOC = "Missing location for {} certificate";

    /**
     * notices a missed KS alias
     * 
     * @param XML
     *            Subject
     */
    public final static String API_ERROR_BUSINESS_GET_ALIASKS = "Getting keystore alias for {} [Unset]";

    /**
     * notices a missed certificate from keystore
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_GET_CERTKS = "Getting certificate from keystore for {} [Failed]";

    /**
     * notices a failed certificate creation from encoded input stream
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CREATE_CERTSTREAM = "Creating certificate from encoded input stream for {} [Failed]";

    /**
     * notices a failed LDAP name creation
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CREATE_LDAPNAME = "Creating LDAP name from {} [Failed]";

    /**
     * notices a NULL XML entity name
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CHECK_XMLENTITYNAME = "Checking XML entity name {} existence [Null]";

    /**
     * notices a NULL XML entity profile name
     * 
     * @param Entity
     *            Profile Name
     */
    public final static String API_ERROR_BUSINESS_CHECK_XMLPROFILENAME = "Checking XML entity profile name {} existence [Null]";

    /**
     * notices a NULL XML keystore list
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CHECK_XMLKSLIST = "Checking XML keystore list for {} [Null]";

    /**
     * notices an invalid XML keystore list entry
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CHECK_XMLKSENTRY = "Checking XML keystore list entry validity for {} [Not Valid]";

    /**
     * notices an invalid XML trust store list entry
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CHECK_XMLTSENTRY = "Checking XML trust store list entry validity for {} [Not Valid]";

    /**
     * notices an invalid XML CRL
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_XMLCRLENTRY = "Checking XML certificate revoking list validity for {} [Not Valid]";

    /**
     * notices an invalid entity info from ENIS check
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_ENISENTITY = "Checking entity info {} [Null/Invalid]";

    /**
     * notices an invalid keystore entry from ENIS check
     * 
     * @param Alias
     *            Keystore Entry
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_BUSINESS_CHECK_ENISKSENTRY = "Checking keystore entry {} for {} [Null/Invalid]";

    /**
     * notices missed trust certificates
     * 
     * @param Entity
     *            Profile Name
     */
    public final static String API_ERROR_BUSINESS_GET_TRUSTCERTS = "Getting trust certificates given {} [Failed]";

    /**
     * notices a NULL trust map chain
     */
    public final static String API_ERROR_BUSINESS_GET_TRUSTCHAIN = "Getting trust map chain [Null]";

    /**
     * notices a NULL CA CRL list
     */
    public final static String API_ERROR_BUSINESS_CHECK_CRLLIST = "Checking CA CRL list[Null]";

    /**
     * notices a NULL wrapper service
     * 
     * @param entityName
     */
    public final static String API_ERROR_HANDLERS_CHECK_WRAPPERNOTNULL = "Checking wrapper SERVICE for {} [Null]";

    /**
     * notices a failed CSR conversion to CredentialManagerPKCS10CertRequest
     */
    public final static String API_ERROR_HANDLERS_CONVERT_CSR = "Converting CSR to CredentialManagerPKCS10CertRequest[Failed]";

    /**
     * notices a NULL signed certificate
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_HANDLERS_CHECK_SIGNEDCERT = "Checking signed certificate for {} [Null]";

    /**
     * notices failed certificate writing
     */
    public final static String API_ERROR_HANDLERS_WRITE_CERTIFICATE = "Writing certificate[Failed]";

    /**
     * notices NULL profile info
     */
    public final static String API_ERROR_HANDLERS_CHECK_PROFILEINFO = "Checking profile info [Null]";

    /**
     * notices failed subjectAltName conversion to CredM subjectAltName
     */
    public final static String API_ERROR_HANDLERS_CONVERT_SUBJECTALTNAME = "Converting subjectAltName to CredM subjectAltName [Failed]";

    /**
     * notices NULL CA CRl list
     * 
     * @param Entity
     *            Profile Name
     */
    public final static String API_ERROR_HANDLERS_CHECK_CRLLIST = "Checking CA CRL list given {} [Null]";

    /**
     * notices failed certificate extension attachment
     */
    public final static String API_ERROR_HANDLERS_ADD_CERTEXTENSION = "Adding certificate extension [Failed]";

    /**
     * notices failed PKCS10 CSR creation
     * 
     * @param End
     *            Entity Name
     */
    public final static String API_ERROR_HANDLERS_CREATE_PKCS10CSR = "Creating PKCS10 CSR for {} [Failed]";

    /**
     * notices trust file invalid location
     */
    public final static String API_ERROR_HANDLERS_CHECK_TSLOC = "Checking Trust File location [Invalid Location]";

    /**
     * notices NULL certificate
     */
    public final static String API_ERROR_HANDLERS_CHECK_CERTIFICATE = "Checking certificate [Null]";

    /**
     * notices NULL key
     */
    public final static String API_ERROR_HANDLERS_CHECK_KEY = "Checking key [Null]";

    /**
     * notices failed PKCS10 CSR creation
     */
    public final static String API_ERROR_BUSINESS_UTILS_CREATE_CSR = "Creating a PKCS10 CSR [Failed]";

    /**
     * notices NULL certificate extension attachment
     */
    public final static String API_ERROR_BUSINESS_UTILS_ADD_CERTEXTENSION = "Adding certificate extension [Null]";

    /**
     * notices failed properties file check
     * 
     * @param Filename
     */
    public final static String API_ERROR_BUSINESS_UTILS_CHECK_PROPERTIESFILE = "Checking properties file {} existence [Failed]";

    /**
     * notices failed input file closure
     * 
     * @param Filename
     */
    public final static String API_ERROR_BUSINESS_UTILS_CLOSE_PROPERTIESFILE = "Closing input file {} [Failed]";

    /**
     * notices failed trust format conversion from cert format
     * 
     * @pararm Cert Format
     */
    public final static String API_ERROR_BUSINESS_UTILS_CONVERT_TRUSTFORMAT = "Converting Trust format from Cert format {} [Failed]";

    /**
     * notices failed storage type check
     * 
     * @param Storage
     *            Type
     */
    public final static String API_ERROR_BUSINESS_UTILS_CHECK_STORAGETYPE = "Checking storage type {} [Failed]";

    /**
     * notices failed private key conversion from PrivateKey to Key
     * 
     * @param Alias
     */
    public final static String API_ERROR_STORAGE_CONVERT_PRIVATEKEY = "Converting private key for {} from PrivateKey to Key [Failed]";

    /**
     * notices failed certificate entry conversion from x509CertificateHolder to X509Certificate
     * 
     * @param Alias
     */
    public final static String API_ERROR_STORAGE_CONVERT_CERT = "Converting certificate entry {} to X509Certificate from x509CertificateHolder [Failed]";

    /**
     * notices failed CRL conversion from X509CRLHolder to CRL
     */
    public final static String API_ERROR_STORAGE_CONVERT_CRLENTRY = "Converting CRL to CRL from X509CRLHolder [Failed]";

    /**
     * notices failed private key attachment to key list
     */
    public final static String API_ERROR_STORAGE_ADD_PRIVATEKEY = "Adding private key to key list [Failed]";

    /**
     * notices failed encryption algorithm reading
     * 
     * @param Certificate
     *            File Path
     */
    public final static String API_ERROR_STORAGE_READ_ENCRYPTALG = "Reading encryption algorithm from {} [Failed]";

    /**
     * notices failed private key creation
     * 
     * @param Private
     *            Key File Path
     */
    public final static String API_ERROR_STORAGE_CREATE_PKFILE = "Creating private key in {} [Failed]";

    /**
     * notices failed certificate file creation
     * 
     * @param Certificate
     *            File Path
     */
    public final static String API_ERROR_STORAGE_CREATE_CERTFILE = "Creating certificate file in {} [Failed]";

    /**
     * notices failed private key and certificate files writing
     * 
     * @param Private
     *            Key File Path
     * @param Certificate
     *            File Path
     */
    public final static String API_ERROR_STORAGE_WRITE_PKCERT = "Writing on private key and certificate files in {} and in {} [Failed]";

    /**
     * notices failed private key and certificate file deletion
     * 
     * @param Private
     *            Key File Path
     * @param Certificate
     *            File Path
     */
    public final static String API_ERROR_STORAGE_DELETE_PKCERT = "Deleting private key and certificate files {} and {} [Failed]";

    /**
     * notices failed writers closure
     */
    public final static String API_ERROR_STORAGE_CLOSE_WRITERS = "Closing writers [Failed]";

    /**
     * notices failed keystore file creation
     * 
     * @param Store
     *            File Path
     */
    public final static String API_ERROR_STORAGE_CREATE_KSFILE = "Creating keystore file {} [Failed]";

    /**
     * notices failed keystore file writing
     * 
     * @param Store
     *            File Path
     */
    public final static String API_ERROR_STORAGE_WRITE_KSFILE = "Writing keystore file {} [Failed]";

    /**
     * notices failed keystore file deletion
     * 
     * @param Store
     *            File Path
     */
    public final static String API_ERROR_STORAGE_DELETE_KSFILE = "Deleting keystore file {} [Failed]";

    /**
     * notices failed CRL file creation
     * 
     * @param Store
     *            File Path
     */
    public final static String API_ERROR_STORAGE_CREATE_CRLFILE = "Creating CRL file in {} [Failed]";

    /**
     * notices failed CRL file writing
     * 
     * @param Store
     *            File Path
     */
    public final static String API_ERROR_STORAGE_WRITE_CRLFILE = "Writing CRL file in {} [Failed]";

    /**
     * notices invalid Credential Manager store type
     * 
     * @param Store
     *            Type
     */
    public final static String API_ERROR_STORAGE_CHECK_STORETYPE = "Checking Credential Manager store type {} [Invalid]";

    /**
     * notices invalid Credential Manager store path
     * 
     * @param Store
     *            File Path
     */
    public final static String API_ERROR_STORAGE_CHECK_STOREPATH = "Checking Credential Manager store path {} [Invalid]";

    /**
     * notices unsupported Credential Manager store type
     * 
     * @param Store
     *            Type
     */
    public final static String API_ERROR_STORAGE_CHECK_UNSUPPSTORETYPE = "Checking Credential Manager store type {} [Unsupported]";

    /**
     * notices if the CRL store is not Base64
     * 
     * @param Store
     *            Type
     */
    public final static String API_ERROR_STORAGE_CHECK_CRLSTORETYPE = "Checking CRL store is Base64 (read {}) [Failed]";

    /**
     * notices missed certificate from keystore
     * 
     * @param Alias
     */
    public final static String API_ERROR_STORAGE_GET_CERTIFICATE = "Getting certificate from keystore {} [Failed]";

    /**
     * notices missed certificate chain from keystore
     * 
     * @param Alias
     */
    public final static String API_ERROR_STORAGE_GET_CERTCHAIN = "Getting certificate chain from keystore {} [Failed]";

    /**
     * notices missed private key from keystore
     * 
     * @param Alias
     */
    public final static String API_ERROR_STORAGE_GET_PK = "Getting private key from keystore {} [Failed]";

    /**
     * notices missed keystore
     */
    public final static String API_ERROR_STORAGE_GET_KS = "Getting keystore [Failed]";

    /**
     * notices missed keystore size
     */
    public final static String API_ERROR_STORAGE_GET_KSSIZE = "Getting keystore size [Failed]";

    /**
     * notices failed keystore loading from file
     * 
     * @param File
     *            Path
     * @param Exception
     *            Stacktrace
     */
    public final static String API_ERROR_STORAGE_LOAD_KS = "Loading keystore from file {} , exception {} [Failed]";

    /**
     * notices failed input stream closure
     * 
     * @param File
     *            Path
     */
    public final static String API_ERROR_STORAGE_CLOSE_INPUTSTREAM = "Closing input stream for {} [Failed]";

    /**
     * notices failed key pair setting in keystore
     * 
     * @param Alias
     */
    public final static String API_ERROR_STORAGE_SETSTORE_KEYPAIRKS = "Setting key pair in keystore {} and storing it away [Failed]";

    /**
     * notices failed output stream closure
     */
    public final static String API_ERROR_STORAGE_CLOSE_OUTPUTSTREAM = "Closing output stream [Failed]";

    /**
     * notices failed certificate setting in keystore
     * 
     * @param Alias
     */
    public final static String API_ERROR_STORAGE_SETSTORE_CERTKS = "Setting certificate in keystore {} and storing it away [Failed]";

    /**
     * notices failed keystore entry deletion
     * 
     * @param Alias
     */
    public final static String API_ERROR_STORAGE_DELETE_ENTRYKS = "Deleting entry keystore {} [Failed]";

    /**
     * notices failed keystore loading with previous data
     * 
     * @param Filename
     */
    public final static String API_ERROR_STORAGE_LOAD_PREVKS = "Loading keystore with previous data in {} [Failed]";
    
    /**
     * notices an error in getEntityByCategory
     * 
     * @param Entity
     *            Name
     */
    public final static String API_ERROR_SERVICE_GET_ENTITY_BY_CATEGORY = "getEntityByCategory {} [Failed]";
    
    /**
     * notices that the category was not found in getEntityByCategory
     * 
     * @param Category
     *            Name
     */
    public final static String API_ERROR_SERVICE_CATEGORY_NOT_FOUND = "getEntityByCategory category not found {} [Failed]";
    
    /**
     * notices an error getting an entity Certificate
     * @param EntityName
     */
    public final static String API_ERROR_BUSINESS_GET_CERTIFICATE = "Getting Certificate for {} [NULL]";
    
}
