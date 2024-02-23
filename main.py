import argparse

from ldaputils import *

p = argparse.ArgumentParser()
d = p.add_argument_group('Default')
d.add_argument('-H', '--host', metavar="", type=str, help='LDAP URI (ex: ldap://192.168.1.100:389)', default="")
d.add_argument('-D', '--domain', metavar="", type=str, help='LDAP DOMAIN (ex: ldap.local)', default="")
d.add_argument('-U', '--user', metavar="", type=str, help='LDAP USER [optional] (ex: Admin)', default="")
d.add_argument('-P', '--password', metavar="", type=str, help='LDAP PASSWORD [optional] (ex: password123)', default="")
d.add_argument('-at', '--auth', metavar="", type=str, help='LDAP AUTH (SIMPLE, NTLM, ANONYMOUS, SASL?)', default="")
d.add_argument('-d', '--dn', metavar="", type=str, help='DN (ex: cn=Users OR cn=Param1,cn=Param2)', default="")
d.add_argument('-t', '--timeout', metavar="", type=int, help='timeout sec in search requests (def: 0)', default=0)
# flags
flags = p.add_argument_group('Files')
flags.add_argument('-tf', '--tofile', action='store_true', help='write all to file (def: out/)')
flags.add_argument('-cc', '--clear', metavar="", type=str, help='clear files in folder (def: out/)')
# sorting
sort = p.add_argument_group('Sort')
sort.add_argument('--sfile', metavar="file", type=str, help='file for sorting')
sort.add_argument('--sfolder', metavar="folder", type=str, help='folder for sorting')
sort.add_argument('--sword', metavar="word", type=str, help='word for sorting')

#files
y = p.add_argument_group('Yara')
y.add_argument('--yara', metavar='[file]', type=argparse.FileType('r'), help='file with yara rules (ex: yara.txt)')
args = p.parse_args()

if args.sfile and args.sfolder and args.sword:
    sortFile(filename=args.sfile, folder=args.sfolder, sortWord=args.sword)
    exit() 

if args.clear:
    print(removeFiles(args.clear))
    exit()

# example
#ldap = LDAP(ldapUri="ldap://192.168.1.104", ldapDomain="dc=ldap,dc=domain,dc=local", ldapUser="Admin", ldapPassword="user@1234")
if args.auth == "ANONYMOUS":
    auth = ANONYMOUS
elif args.auth == "NTLM":
    auth = NTLM
elif args.auth == "SASL":
    auth = SASL
else:
    auth = SIMPLE

if args.host != "":
    print("=====Connecting=====")
    print(f"Host: {args.host}")
    print(f"Auth: {auth}")
    print(f"User: {str(args.domain)}\\{args.user}")
    print(f"Password: {args.password}")
    print("====================")
    ldap = LDAP(ldapUri=args.host, ldapDomain=args.domain, ldapUser=args.user, ldapPassword=args.password, ldapAuth=auth)
else:
    print("Indicate: -H host -D domain\nGet full info: -h/--help")
    exit()

    
if args.tofile or args.yara:
    print("Writing to files...")
    if args.yara:
        ldap.toFile(yarafile=args.yara, timeout=args.timeout)
    else:
        ldap.toFile(folder="out/", timeout=args.timeout, clear_old_files=True) # example
else:
    # simple print from generator
    for i in ldap.search(DN=args.dn):
        print(i)
        


print(ldap.unbind())

# Использование значения аргумента
# print(f"Введенное слово: {args.word}")
# if args.i:
#     print("wewe i")