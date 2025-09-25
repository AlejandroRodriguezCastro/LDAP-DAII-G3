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
