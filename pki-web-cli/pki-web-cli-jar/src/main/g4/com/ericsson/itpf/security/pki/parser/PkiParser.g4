parser grammar PkiParser;

import PkiBaseParser;

options {
	tokenVocab = PkiLexer;
}

/*
Defining new command: STEP 2 and 3  (for STEP 1 see PkiLexer.g4 file)

2- Create a new rule representing your command syntax. A new rule has the following format :

    <rule name> :
        <command entry defined in PkiLexer.g4 file> <parameter definition>
    ;

    - "parameter definition" can be zero or more of the below functions:

        Observation: <param name> or <prop1> = the name that will be used as Key of Map returned by the parser

        FUNCTION                                                        DESCRIPTION
        textValue["<param name>"]                                       Any text value parameter.
        textValueFromList["<param name>", list("<opt1>","<optn>")]      Any text value parameter, but it has to be one of provided options,
                                                                        otherwise it is considered a syntax error.
        intValue["<param name>"]                                        A int parameter
        fileValue["<param name>"]                                       A parameter that specifies a file name. Has to be in the format:
                                                                            file=<file name>
        listValue["<param name>"]                                       A parameter made of one or more values. Expects as single value like ' val1 '
                                                                        or a list in the format : ' val1, val2, val3; '
        property                                                        A parameter in the format : -key value . This parameter will be added to resulting
                                                                        Map as is, but dashes at the beginning of the property name will be discarted.
        propertyFromList[list("<prop1>","<propn>")]                     Same as 'property' but the KEY has to be one of provided options
                                                                        otherwise it is considered a syntax error.
        propertyValueFromList["<prop1>",list("<opt1>","<optn>")]        Same as 'property' but the VALUE has to be one of provided options
                                                                        otherwise it is considered a syntax error.
        propertyList                                                    Expects one or more 'property' separated by spaces
        propertyListFromList[list("<prop1>","<propn>")]                 Same as 'propertyList' but keys have to be among provided options
                                                                        otherwise it is considered a syntax error.
        propertyFromListWithoutValue[list("<prop1>","<propn>")]         Same as 'propertyFromList' but the value is not required. If value is there ,
        																then we should use propertyFromList.
        propertyListFromListWithoutValue[list("<prop1>","<propn>")] 	Same as 'propertyListFromList' but all properties must not have any value

        ALIASES:
            Properties can have aliases. To define a property with alias use the function withAlias("<prop>","<alias1>","<aliasn>"). Eg.:

                propertyFromList[ list(withAlias("--nodelist:list","-n")) ]

3- Add new rule to the list of possible commands in main rule called 'command'

                                                        insert rule name here
                                                                |
    command:                                                    v
        (certificateIssue|<rule name>) ...

*/

command :
    ( configmgmtenable |  configmgmtdisable | configmgmtcategorycreate | configmgmtcategoryupdate| configmgmtcategorylist| configmgmtcategorydelete )
    | ( configmgmtlist  | profilemgmtimport | entitymgmtimport | profilemgmtcreate )
    | ( profilemgmtexport (profilebased | allselection) allfields? )
    | ( profilemgmtlist (profilebased | allselection))
    | ( entitymgmtexport (entitybased | allselection) allfields? )
    | ( profilemgmtupdate  xmlfile )
    | ( profilemgmtdelete (profilebaseddelete | xmlfile))
    | ( cacertificatemanagementgenerate | cacertificatemanagementreissue | cacertificatemanagementlist | cacertificatemanagementexport | cacertificatemanagementlisthierarchy | certificatemanagementlist | certificatemanagementgeneratecsr | certificatemanagementimport)
   | ( eecertificatemgmtgenerate | eecertificatemgmtgeneratewithoutcsr |eecertificatemgmtreissue | eecertificatemgmtlist | secgwcertmanagement)
   | ( entitymanagementcreate | entitymanagementlist | entitymanagementupdate | entitymanagementdelete | eecertificatemanagementexport )
   | ( externalcacertimport )
   | ( externalcaupdatecrl )
   | ( externalcalist ) 
   | ( externalcaremove ) 
   | ( externalcacertexport )
   | ( externalcaconfigcrl )
   | ( externalcaremovecrl )
   | ( revocationmanagementrevokeca | revocationmanagementrevokeee)
   | ( profilemgmtview )
   | (crlmanagementgenerate | crlmanagementlist  | crlmanagementdownload |crlmanagementpublish | crlmanagementunpublish)
   | ( trustmanagementpublish | trustmanagementunpublish | trustmanagementlist | trustmanagementlistbystatus)
   
;


/*External CA Certificate Management */

certificatemanagementimport :
CERTIFICATEMANAGEMENTIMPORT caentityname extcacertificate careissuetype rfcvalidation force?
; 

/*CRL Management */

crlmanagementpublish :
CRLMANAGEMENTPUBLISH caentityname
;

crlmanagementunpublish :
CRLMANAGEMENTUNPUBLISH caentityname
;

/*Trust Management */

trustmanagementpublish :
    TRUSTMANAGEMENTPUBLISH entitytype entityname
;

trustmanagementunpublish :
    TRUSTMANAGEMENTUNPUBLISH entitytype entityname
;

trustmanagementlist :
	TRUSTMANAGEMENTLIST entitytype entityname?
;

trustmanagementlistbystatus :
	TRUSTMANAGEMENTLISTBYSTATUS entitytype tdpscertificatestatus?
;

tdpscertificatestatus :
	propertyFromList[list(withAlias("--certstatus", "-cs"))]
;

/*CRL Management */

crlmanagementgenerate :
CRLMANAGEMENTGENERATE caentityname entityselection  
;

crlmanagementdownload :
CRLMANAGEMENTDOWNLOAD caentityname downloadselection 
;

crlmanagementlist :
CRLMANAGEMENTLIST caentityname crllistselection count
;

/* Revocation Management */
revocationmanagementrevokeca :
REVOCATIONMANAGEMENTREVOKECACERT revokeidentification revocationreason? invaliditydate? 
;

revocationmanagementrevokeee :
REVOCATIONMANAGEMENTREVOKEENTITYCERT revokeidentification revocationreason? invaliditydate? 

;

/* CA Certificate Management */
cacertificatemanagementgenerate
:
	CACERTIFICATEMANAGEMENTGENERATE entityname ( formatoptions | nopopup ) 
;

cacertificatemanagementreissue
:
	CACERTIFICATEMANAGEMENTREISSUE entityname reissuetype level revoke?
	
;

cacertificatemanagementlist
:
	CACERTIFICATEMANAGEMENTLIST entityname certstatus?
;



cacertificatemanagementexport
:
	CACERTIFICATEMANAGEMENTEXPORT entityname formatoptions
;


cacertificatemanagementlisthierarchy :
	CACERTIFICATEMANAGEMENTLISTHIERARCHY hierarchyselection

;


certificatemanagementlist
:
	CERTIFICATEMANAGEMENTLIST cacertificateidentifier certificatestatus?
;

certificatemanagementgeneratecsr :
	CERTIFICATEMANAGEMENTGENERATECSR caentityname newkey force?
;

/* Entity Certificate Management */
eecertificatemgmtgenerate
:
	ENTITYCERTMANAGEMENTGENARATE entityname file_name ( formatoptions | nopopup ) 
;
 
secgwcertmanagement
:
    SECGWCERTMANAGEMENT certtype file_name nochain?
;

eecertificatemgmtgeneratewithoutcsr
:
	ENTITYCERTMANAGEMENTGENARATEWITHOUTCSR entityname certchainwithoutcsr

;

eecertificatemgmtreissue
:
	ENTITYCERTMANAGEMENTREISSUE entityname eereissuetype
;

renewandmodification
:
	renewtype file_name
;

rekey
:
	rekeylist password format
;

eecertificatemgmtlist
:
	ENTITYCERTMANAGEMENTLIST entityname certstatus
;


eecertificatemanagementexport
:
	ENTITYCERTMANAGEMENTEXPORT entityname formatoptions
;


configmgmtenable
:
	CONFIGMGMTENABLE configopts
;

configmgmtdisable
:
	CONFIGMGMTDISABLE configopts
;

configmgmtlist
:
	CONFIGMGMTLIST configlistopts
;

configmgmtcategorycreate
:
	CONFIGMANAGEMENTCATEGORYCREATE categorycreate
	
		
;

configmgmtcategoryupdate
:
	CONFIGMANAGEMENTCATEGORYUPDATE categoryupdate
	
		
;

configmgmtcategorylist
:
	CONFIGMANAGEMENTCATEGORYLIST givenname?
	
		
;

configmgmtcategorydelete
:
	CONFIGMANAGEMENTCATEGORYDELETE categorydelete
	
		
;

profilemgmtimport
:
	PROFILEMANAGEMENTIMPORT xmlfile
;

profilemgmtexport
:
	PROFILEMANAGEMENTEXPORT
;

profilemgmtlist
:
	PROFILEMANAGEMENTLIST
;

profilemgmtcreate
:
	PROFILEMANAGEMENTCREATE xmlfile
;

profilemgmtupdate
:
	PROFILEMANAGEMENTUPDATE

;

profilemgmtdelete
:
	PROFILEMANAGEMENTDELETE
;

profilemgmtview
:
	PROFILEMANAGEMENTVIEW profiletype givenname
;
externalcacertimport
:
	EXTERNALCACERTIMPORT externalcaimportparameter
;

externalcacertexport
:
	EXTERNALCACERTEXPORT externalcaexportparameter
;

externalcaupdatecrl
:
	EXTERNALCAUPDATECRL externalcaupdatecrlparameter
;

externalcaconfigcrl
:
	EXTERNALCACONFIGCRL externalcaconfigcrlparameter
;


externalcalist
:
	EXTERNALCALIST givenname?
;

externalcaimportparameter 
:
	propertyListFromList [list(withAlias("--filename:file", "-fn"),
		            withAlias("--chainrequired", "-cr"),
		            withAlias("--name", "-n"),
		            withAlias("--rfcvalidation", "-rv")
	)]
;

externalcaexportparameter 
:
	propertyListFromList [list(
							withAlias("--serialnumber", "-sn"),
							withAlias("--name", "-n"))]
;

externalcaremove
:
	EXTERNALCAREMOVE givenname
;

externalcaupdatecrlparameter
:
	propertyListFromList [list(
							withAlias("--filename:file", "-fn"),
							withAlias("--name", "-n"),
							"-url")]
;

externalcaconfigcrlparameter
:
	propertyListFromList [list(withAlias("--autoupdate", "-au"), 
							withAlias("--name", "-n"),
							withAlias("--timer", "-t"))]
;

externalcaremovecrl
:
    EXTERNALCAREMOVECRL externalcaremovecrlparameter
;

externalcaremovecrlparameter
:
	propertyListFromList [list(
							withAlias("--issuername", "-in"),
							withAlias("--name", "-n"))]
;








serialnumber
:
	(
		propertyFromList [list(withAlias("--serialnumber", "-sn"))]
	)
;

profilebasedfield
:
	profilebased fieldtoreplace
;

profilebaseddelete
:
	profiletype givenname

;

custombasedfield
:
	pcustomselection fieldtoreplace
;

allselectionfield
:
	allselection fieldtoreplace
;

entitymgmtimport
:
	ENTITYMANAGEMENTIMPORT xmlfile
;

entitymgmtexport
:
	ENTITYMANAGEMENTEXPORT
;

entitymanagementcreate
:
	ENTITYMANAGEMENTCREATE xmlfile
;

entitymanagementlist
:
	ENTITYMANAGEMENTLIST listselection
;

entitymanagementupdate
:
	ENTITYMANAGEMENTUPDATE
	(
		(
			updateselection fieldtoreplace
		)
		| xmlfile
	)
;

entitymanagementdelete
:
	ENTITYMANAGEMENTDELETE deleteselection
;

entitymanagementsync
:
	ENTITYMANAGEMENTSYNC entitybased
;

configopts
:
	givenname keysize?
;

enable
:
	(
		propertyFromListWithoutValue [list(withAlias("--enable", "-e"))]
	)
;

disable
:
	(
		propertyFromListWithoutValue [list(withAlias("--disable", "-d"))]
	)
;


configlistopts
:
	algotype algostatus
;

givenname
:
	(
		propertyFromList [list(withAlias("--name", "-n"))]
	)
;

keysize
:
	(
		propertyFromList [list(withAlias("--keysize", "-ks"))]
	)
;

algotype
:
	propertyFromListWithValue
	[list(withAlias("--type", "-t")), list("signature", "digest", "asymmetric", "symmetric", "all" )]
;

algostatus
:
	propertyFromListWithValue
	[list(withAlias("--status", "-s")), list("enabled", "disabled", "all")]
;

xmlfile
:
	(
		propertyFromList [list(withAlias("--xmlfile:file", "-xf"))]
	)
;

certfile
:
	(
		propertyFromList [list(withAlias("--filename:file", "-fn"))]
	)
;

profilebased
:
	profiletype givenname?
;

entitybased
:
	entitytype givenname?
;

profiletype
:
	propertyFromListWithValue
	[list(withAlias("--profiletype", "-type")),list("certificate", "entity", "trust")]
;

entitytype
:
	propertyFromListWithValue
	[list(withAlias("--entitytype", "-type")), list("ca", "ee")]
;

pcustomselection
:
	profiletype fieldmapping
;

ecustomselection
:
	entitytype fieldmapping
;

fieldmapping
:
	(
		propertyFromListWithoutValue [list(withAlias("--match", "-m"))]
	)
	(
		property
	)*

;

allselection
:
	(
		propertyFromListWithoutValue [list(withAlias("--all", "-a"))]
	)
;

fieldtoreplace
:
	(
		propertyFromListWithoutValue [list(withAlias("--replace", "-r"))]

	)
	(
		property
	)*
;

renewtype
:
	(
		propertyFromListWithValue
		[list(withAlias("--renewtype", "-type")), list("renew", "modification")]
	)
;

certstatus
:
	propertyFromListWithValue
	[list(withAlias("--status", "-s")), list("active", "inactive", "revoked", "expired")]
;

file_name
:
	propertyFromList
	[list(withAlias("--csrfile:file", "-csr"), withAlias("--crmffile:file", "-crm"))]
	;
	
certtype :
    propertyFromListWithValue
    [list(withAlias("--certtype", "-ct")), list("OAM", "Traffic")]
;    

entityname :
    propertyFromList[list(withAlias("--entityname", "-en"))]
;

rekeylist
:
	propertyFromListWithValue
	[list(withAlias("--renewtype", "-type")), list("rekey")]
;

format
:
	propertyFromListWithValue
	[list(withAlias("--format", "-f")), list("JKS", "P12", "JCEKS", "PEM")]
;

password
:
	(
		propertyFromList [list(withAlias("--password", "-pass"))]
	)
;

nopopup:
propertyFromListWithoutValue [list(withAlias("--nopopup","-npop"))]
; 

nochain:
propertyFromListWithoutValue [list(withAlias("--nochain", "-nch"))]
;

reissuetype
:
	(
		propertyFromListWithValue
		[list(withAlias("--reissuetype", "-rt")), list("renew", "rekey")]
		
	)
;

eereissuetype
:
	(
		propertyFromListWithValue
		[list(withAlias("--reissuetype", "-rt")), list("renew")]
		(
		propertyFromList
	    [list(withAlias("--csrfile:file", "-csr"), withAlias("--crmffile:file", "-crm"))]

	) | 
	    propertyFromListWithValue
		[list(withAlias("--reissuetype", "-rt")), list("rekey")]
		(
		propertyFromList [list(withAlias("--password", "-pass"))]?

		propertyFromListWithValue
	    [list(withAlias("--format", "-f")), list("JKS", "P12")]

	   )
	)
;

level
:
	(
		propertyFromListWithValue
		[list(withAlias("--level", "-le")), list("CA","CA_IMMEDIATE_SUB_CAS", "CA_ALL_CHILD_CAS")]
	)
;

revoke :
(
	propertyFromListWithoutValue [list(withAlias("--revoke", "-r"))]
)

;

deleteselection
:
	(
		propertyFromListWithValue
		[list(withAlias("--entitytype", "-type")), list("ca", "ee")]
		(

			propertyFromList[list(withAlias("--name", "-n"))] 
		)
		| xmlfile			
	)
;

listselection
:
	(
		entitytype 		
		propertyFromList[list(withAlias("--name", "-n"),withAlias("--category", "-cat"))]?
	)
;

updateselection
:
	(
		propertyFromListWithValue
		[list(withAlias("--entitytype", "-type")), list("ca", "ee")]
		(
			propertyFromList [list(withAlias("--name", "-n"))]?
		)
		| propertyFromListWithoutValue [list(withAlias("--all", "-a"))]
	)
	| xmlfile
;


categorycreate
:
     givenname
	
;		


categoryupdate
:
		
	  propertyFromList [list(withAlias("--oldname", "-on"))]
	  propertyFromList [list(withAlias("--newname", "-nn"))]
;	


categorydelete
:	
	givenname
		
;

formatoptions
:
	format ( password? nochain? )

;

certchainwithoutcsr
:
	propertyFromListWithValue
	[list(withAlias("--format", "-f")), list("JKS", "P12")]
	 ( password? nochain? )
;


hierarchyselection :
    propertyFromList[list(withAlias("--name", "-n"))] 
	| propertyFromListWithoutValue[list(withAlias("--all", "-a"))]
	


;

certchainforendentity
:
	propertyFromListWithValue
	[list(withAlias("--format", "-f")), list("JKS", "P12","PEM", "DER")]
	(
		propertyFromList [list(withAlias("--password", "-pass"))]?
		propertyFromListWithoutValue [list(withAlias("--nochain", "-nch"))]?
	)| propertyFromListWithoutValue [list(withAlias("--nopopup","-npop"))]
;

revokeidentification
 :
(propertyFromList[list(withAlias("--entityname", "-en"))] 
		|(
			(propertyFromList[list(withAlias("--issuername", "-isrn"))])
			(propertyFromList[list(withAlias("--serialno", "-sno"))]) 
		  )
		| (
			(propertyFromList[list(withAlias("--subjectDN", "-subDN"))])
			(propertyFromList[list(withAlias("--issuerDN", "-isrDN"))])
			(propertyFromList[list(withAlias("--serialno", "-sno"))]) 
		  )
)
;
		
revocationreason 
:
  propertyFromList[list(withAlias("--reasontext", "-rt"),withAlias("--reasoncode", "-rc"))] 
;
   
 
cacertificateidentifier
 : 
 (
 (propertyFromList[list(withAlias("--caentityname", "-caen"))])
 (propertyFromList[list(withAlias("--serialno", "-sno"))]) 
 )
;

invaliditydate 
:
(propertyFromList[list(withAlias("--invaliditydate", "-ind"))])
;

caentityname :

(
	propertyFromList[list(withAlias("--caentityname", "-caen"))]
)

;

entityselection 
: 
  propertyFromList[list(withAlias("--serialno", "-sno"),withAlias("--status", "-s"))]? 
;

downloadselection :
( 
	propertyFromList[list(withAlias("--serialno", "-sno"),withAlias("--status", "-s"),withAlias("--crlnumber", "-cn"))]
)	
;

crllistselection 
:
(
	propertyFromList[list(withAlias("--serialno", "-sno"),withAlias("--status", "-s"))] 
  	
  )
    
;

	
certificatestatus :
	propertyFromList[list(withAlias("--status", "-s"))]
	;



count 
:
(
 propertyFromList[list(withAlias("--count", "-c"))]
) 
;


newkey
:
	propertyFromListWithValue
	[list(withAlias("--newkey", "-nk")), list("true", "false")]
;

force:	
	propertyFromListWithoutValue[list(withAlias("--force", "-fc"))]	
;

extcacertificate 
:(
	propertyFromList[list(withAlias("--certificate:file", "-c"))]	
)
;

careissuetype
:(
   propertyFromListWithValue[list(withAlias("--careissuetype", "-crt")),list("RENEW_SUB_CAS","RENEW_SUB_CAS_WITH_REVOCATION","REKEY_SUB_CAS","REKEY_SUB_CAS_WITH_REVOCATION","NONE")]	
)
;

rfcvalidation
:(
	propertyFromListWithValue[list(withAlias("--rfcvalidation", "-rv")),list("true","false")]
)
;

chainrequired 
:(
	propertyFromListWithValue
	[list(withAlias("--chainrequired", "-cr")), list("true", "false")]
)
;

allfields:
	propertyFromListWithoutValue[list(withAlias("--allfields", "-af"))]
;
