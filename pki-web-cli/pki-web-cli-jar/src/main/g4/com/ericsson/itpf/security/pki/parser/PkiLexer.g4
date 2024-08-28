lexer grammar PkiLexer;


CONFIGMGMTLIST : ('configmgmt algo' | 'cfg algo') ' ' ('--list' | '-l') -> mode(inside_command);

CONFIGMGMTENABLE  : ('configmgmt algo' | 'cfg algo') ' ' ('--enable'| '-e') -> mode(inside_command);

CONFIGMGMTDISABLE  : ('configmgmt algo' | 'cfg algo') ' ' ('--disable'| '-d') -> mode(inside_command);


PROFILEMANAGEMENTIMPORT : ('profilemgmt'| 'pfm') ' ' ('--createbulk' | '-cb') -> mode(inside_command);

PROFILEMANAGEMENTEXPORT : ('profilemgmt'| 'pfm') ' ' ('--export' | '-ex') -> mode(inside_command);

PROFILEMANAGEMENTCREATE : ('profilemgmt'| 'pfm') ' ' ('--create' | '-c') -> mode(inside_command);

PROFILEMANAGEMENTLIST : ('profilemgmt'| 'pfm') ' ' ('--list' | '-l') -> mode(inside_command);

PROFILEMANAGEMENTDELETE : ('profilemgmt'| 'pfm') ' ' ('--delete' | '-d') -> mode(inside_command);

PROFILEMANAGEMENTUPDATE : ('profilemgmt'| 'pfm') ' ' ('--update' | '-u') -> mode(inside_command);

ENTITYMANAGEMENTIMPORT: ('entitymgmt'| 'etm') ' ' ('--createbulk' | '-cb') -> mode(inside_command);

ENTITYMANAGEMENTEXPORT: ('entitymgmt'| 'etm') ' ' ('--export' | '-ex') -> mode(inside_command);

ENTITYMANAGEMENTCREATE : ('entitymgmt' | 'etm') ' ' ('--create' | '-c') -> mode(inside_command);

ENTITYMANAGEMENTLIST : ('entitymgmt' | 'etm') ' ' ('--list' | '-l') -> mode(inside_command);

ENTITYMANAGEMENTUPDATE : ('entitymgmt' | 'etm') ' ' ('--update' | '-u') -> mode(inside_command);

ENTITYMANAGEMENTDELETE : ('entitymgmt' | 'etm') ' ' ('--delete' | '-d') -> mode(inside_command);

EXTERNALCACERTIMPORT : ('extcaimport')  -> mode(inside_command);

EXTERNALCAUPDATECRL : ('extcaupdatecrl')   -> mode(inside_command);

EXTERNALCACONFIGCRL : ('extcaconfigcrl')   -> mode(inside_command);

EXTERNALCALIST : ('extcalist')  -> mode(inside_command);

EXTERNALCAREMOVE : ('extcaremove')  -> mode(inside_command); 

EXTERNALCACERTEXPORT : ('extcaexport')  -> mode(inside_command);

EXTERNALCAREMOVECRL : ('extcaremovecrl')  -> mode(inside_command);

CACERTIFICATEMANAGEMENTGENERATE : ('certmgmt' | 'ctm') ' ' ('CACert') ' ' ('--generate' | '-gen') -> mode(inside_command);

CACERTIFICATEMANAGEMENTREISSUE : ('certmgmt' | 'ctm') ' ' ('CACert') ' '  ('--reissue' | '-ri') -> mode(inside_command);

CACERTIFICATEMANAGEMENTLIST : ('certmgmt' | 'ctm') ' ' ('CACert') ' '  ('--list' | '-l') -> mode(inside_command);

CACERTIFICATEMANAGEMENTEXPORT : ('certmgmt' | 'ctm') ' ' ('CACert') ' ' ('--exportcert' | '-expcert' ) -> mode(inside_command);

CACERTIFICATEMANAGEMENTLISTHIERARCHY : ('certmgmt' | 'ctm') ' ' ('CACert') ' '  ('--listhierarchy' | '-lh') -> mode(inside_command);

CERTIFICATEMANAGEMENTLIST : ('certmgmt' | 'ctm') ' ' ('--list' | '-l') -> mode(inside_command);

CERTIFICATEMANAGEMENTGENERATECSR : ('certmgmt' | 'ctm') ' ' ('--generatecsr' | '-gc') -> mode(inside_command);

CERTIFICATEMANAGEMENTIMPORT : ('certmgmt' | 'ctm') ' ' ('--importcert' | '-im') -> mode(inside_command);



SECGWCERTMANAGEMENT : ('certmgmt' | 'ctm') ' ' ('SecGW') ' ' ('--generate' | '-gen') -> mode(inside_command);

ENTITYCERTMANAGEMENTGENARATE : ('certmgmt' | 'ctm') ' ' ('EECert') ' ' ('--generate' | '-gen') -> mode(inside_command);

ENTITYCERTMANAGEMENTGENARATEWITHOUTCSR : ('certmgmt' | 'ctm') ' ' ('EECert') ' ' ('--generate' | '-gen') ' ' ('-nocsr') -> mode(inside_command);

ENTITYCERTMANAGEMENTREISSUE : ('certmgmt' | 'ctm') ' ' ('EECert') ' ' ('--reissue' | '-ri') -> mode(inside_command);

ENTITYCERTMANAGEMENTLIST : ('certmgmt' | 'ctm') ' ' ('EECert') ' ' ('--list' | '-l') -> mode(inside_command);

ENTITYCERTMANAGEMENTEXPORT : ('certmgmt' | 'ctm') ' ' ('EECert') ' ' ('--exportcert' | '-expcert' ) -> mode(inside_command);

 

CONFIGMANAGEMENTCATEGORYCREATE : ( 'configmgmt' | 'cfg') ' ' ('category') ' ' ('--create' | '-c') -> mode(inside_command);

CONFIGMANAGEMENTCATEGORYUPDATE : ( 'configmgmt' | 'cfg') ' ' ('category') ' ' ('--update' | '-u') -> mode(inside_command);

CONFIGMANAGEMENTCATEGORYLIST : ( 'configmgmt' | 'cfg') ' ' ('category') ' ' ('--list' | '-l') -> mode(inside_command);

CONFIGMANAGEMENTCATEGORYDELETE : ( 'configmgmt' | 'cfg') ' ' ('category') ' ' ('--delete' | '-d') -> mode(inside_command);

REVOCATIONMANAGEMENTREVOKECACERT : ('revmgmt' | 'rem') ' ' ('CA') ' ' ('--revoke' | '-rev') -> mode(inside_command);

REVOCATIONMANAGEMENTREVOKEENTITYCERT : ('revmgmt' | 'rem') ' ' ('EE') ' ' ('--revoke' | '-rev') -> mode(inside_command);


PROFILEMANAGEMENTVIEW : ('profilemgmt'| 'pfm') ' ' ('--view' | '-v') -> mode(inside_command);




CRLMANAGEMENTGENERATE : ('crlmgmt' | 'crm') ' ' ('--generate' | '-g') -> mode(inside_command);

CRLMANAGEMENTLIST : ('crlmgmt' | 'crm') ' ' ('--list' | '-l') -> mode(inside_command);

CRLMANAGEMENTDOWNLOAD : ('crlmgmt' | 'crm') ' ' ('--download' | '-dl') -> mode(inside_command);



TRUSTMANAGEMENTPUBLISH  : ('trustmgmt' | 'tsm') ' ' ('--publish' | '-pub')  -> mode(inside_command);

TRUSTMANAGEMENTUNPUBLISH  : ('trustmgmt' | 'tsm') ' ' ('--unpublish' | '-up')  -> mode(inside_command);

CRLMANAGEMENTPUBLISH : ('crlmgmt' | 'crm') ' ' ('--publish' | '-pub') -> mode(inside_command);

CRLMANAGEMENTUNPUBLISH : ('crlmgmt' | 'crm') ' ' ('--unpublish' | '-up') -> mode(inside_command);

TRUSTMANAGEMENTLIST : ('trustmgmt' | 'tsm') ' ' ('--list' | '-l') -> mode(inside_command);

TRUSTMANAGEMENTLISTBYSTATUS : ('trustmgmt' | 'tsm') ' ' ('--list' | '-l') ' ' ('status') -> mode(inside_command);




/* ==== DO NOT WRITE ANYTHING BELOW THIS POINT UNLESS YOU KNOW EXACTLY WHAT YOU ARE DOING ====*/

mode inside_command;

FILE : 'file:' ;

INT : [0-9]+;

TEXT : [a-zA-Z0-9_%@#$!?=-]+;

FILENAME : FILE(TEXT | QUOTED_TEXT | INT | [\./])+ ;

PROPERTY_PREFIX : '--'|'-' ;

fragment WS : [ \t\r\n]+;
WHITESPACE : WS -> skip;

//Separator in the node list
LIST_END : ';' ;
DOUBLE_QUOTES : '"' -> skip, mode(inside_quotes);
COMMA : ',';
SQUARE_BRACKET_OPEN : '[' ;
SQUARE_BRACKET_CLOSE : ']' ;
COLON : ':';
EQ : '=';

mode inside_quotes;
ESCAPED_QUOTE : '\\"'  -> more;
QUOTED_TEXT : '"' ->  type(TEXT), mode(inside_command);
CHAR : .  -> more;
