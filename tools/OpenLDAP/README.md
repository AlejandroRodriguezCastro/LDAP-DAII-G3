#1 Create Orgs

# In container:


----
1

ldapadd -Y EXTERNAL -H ldapi:/// <<EOF
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: ppolicy.la
EOF


----
2

ldapadd -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcOverlay=ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: ppolicy
olcPPolicyDefault: cn=default,ou=policies,dc=ldap,dc=com
EOF

-----
3

ldapadd -x -D "cn=admin,dc=ldap,dc=com" -W <<EOF
dn: ou=policies,dc=ldap,dc=com
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,dc=ldap,dc=com
objectClass: pwdPolicy
objectClass: person
objectClass: top
cn: default
sn: default
pwdAttribute: userPassword
pwdMaxFailure: 3
pwdLockout: TRUE
pwdLockoutDuration: 300
pwdInHistory: 5
pwdCheckQuality: 2
EOF


----
If error:
sudo ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=config" "(objectClass=olcDatabaseConfig)" dn

----



# echo  "dn: cn=loginRecord,cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: loginRecord\nolcAttributeTypes: ( 1.3.6.1.4.1.9999.3.1 NAME 'loginIP' DESC 'IP address used for login' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )\nolcAttributeTypes: ( 1.3.6.1.4.1.9999.3.2 NAME 'loginTimestamp' DESC 'Timestamp of login' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )\nolcObjectClasses: ( 1.3.6.1.4.1.9999.3.3 NAME 'loginRecord' DESC 'Represents a user login event' SUP top STRUCTURAL MUST ( loginIP \$ loginTimestamp ) )" >> loginRecord.ldif
# ls
loginRecord.ldif  loginRecord.schema
# cat loginRecord.ldif
dn: cn=loginRecord,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: loginRecord
olcAttributeTypes: ( 1.3.6.1.4.1.9999.3.1 NAME 'loginIP' DESC 'IP address used for login' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.9999.3.2 NAME 'loginTimestamp' DESC 'Timestamp of login' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.9999.3.3 NAME 'loginRecord' DESC 'Represents a user login event' SUP top STRUCTURAL MUST ( loginIP $ loginTimestamp ) )
# ldapadd -Y EXTERNAL -H ldapi:/// -f loginRecord.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=loginRecord,cn=schema,cn=config"