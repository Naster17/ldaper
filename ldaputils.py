import os
# import ldap
import ldap3
from ldap3 import Server, Connection, NTLM, SIMPLE, ANONYMOUS, SASL, SUBTREE, LEVEL, ALL_ATTRIBUTES, ALL

import binascii

from time import sleep

# split file by word
def sortFile(filename="Computers", folder="out/", sortWord="operatingSystem"):
    """Мощьный инструмент для сортировки файлов на под файлы, по указаному слову
        ### Имя файла для сортировки
        filename: Computers
        ### Папка с файлом
        folder: out/
        ### Слово для сортировки
        sortWord: operatingSystem"""
    DN=""; PC=""
    try:
        with open(folder+filename, 'r') as file:
            content = file.read()

            # Split text to blocks
            blocks = content.split('DN:')[1:]

            # make dict for group items
            grouped_blocks = {}
            for block in blocks:
                operating_system = next((line.split(':', 1)[1].strip() for line in block.split('\n') if line.startswith(sortWord+':')), None)
                if operating_system not in grouped_blocks:
                    grouped_blocks[operating_system] = []
                grouped_blocks[operating_system].append(block)

            # Write blocks to files
            for operating_system, blocks_in_group in grouped_blocks.items():
                file_name = f"{folder}{operating_system}"
                with open(file_name, 'w') as grouped_file:
                    grouped_file.write("DN:" + "".join(blocks_in_group))
                    
    except Exception as e:
        print(f"Error: {e}\nMaybe file or folder not found")

def removeFiles(folder="out/"):
    """Удалиения файлов в указаной папке
        ### папка
        folder: out/ """
    try:
        file_list = os.listdir(folder)

        for file_name in file_list:
            file_path = os.path.join(folder, file_name)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except: pass
    except: pass
    return "cleared: "+folder


def toHex(obj):
    hexx = binascii.hexlify(obj).decode('utf-8')
    return hexx 


class LDAP:
    def __init__(self, ldapUri, ldapDomain, ldapUser, ldapPassword, ldapAuth) -> None:
        """Инициализация класса
           ### юри сервера
           ldapUri="ldap://192.168.1.100"
           ### домен лдап 
           ldapDomain="dc=ldap,dc=domain,dc=local"
           ### пользователь с правами к лдап
           ldapUser="Admin"  
           ### пароль пользователя
           ldapPassword='password123'"""
        self.ldapUri = ldapUri
        self.ldapDomain = ldapDomain
        self.ldapUser = ldapUser if ldapUser else ""
        self.ldapPassword = ldapPassword if ldapPassword else ""
        self.ldapAuth = ldapAuth if ldapAuth else SIMPLE
        # Список который содержыт символы которые нужено перевести в hex 
        self.hexlist = ['objectSid', 'objectGUID', 'dnsRecord', 'auditingPolicy', 'dSASignature'
                        'samDomainUpdates', 'msDFSR-ReplicationGroupGuid', 'ipsecData', 'samDomainUpdates'
                        'msDS-AdditionalDnsHostName', 'dSASignature', 'msDS-AdditionalDnsHostName', 'msDFSR-ContentSetGuid']
        
        self.connect() 
        

    # default using to connect 
    def connect(self):
        """### Базовое подключение"""
        try:
            # old python-ldap 
            # self.conn = ldap.initialize(self.ldapUri)
            # self.conn.simple_bind_s(self.ldapUser, self.ldapPassword)
            
            server = Server(self.ldapUri, get_info=ALL)
            
            if self.ldapAuth == NTLM:
                print("Generating NTLM...")
            else:
                print("Loading...")
            
            if self.ldapAuth == ANONYMOUS:    
                self.conn = Connection(server, user='', password=self.ldapPassword, authentication=self.ldapAuth)
            else:
                self.conn = Connection(server, user=f'{self.ldapDomain}\\{self.ldapUser}', password=self.ldapPassword, authentication=self.ldapAuth)

            if not self.conn.bind():
                print('Authenticated Failed')
                exit(1);
            print('Authentication Success')
                
        except Exception as e:
            print("Error connecting to LDAP:", e)
            
    # default unbind/close connection
    def unbind(self):
        """### Отключения и анбинд"""
        self.conn.unbind() 
        return "Connection closed"

    # default search method (generator)                                SCOPE_ONELEVEL , SCOPE_SUBTREE , SCOPE_BASE  
    def search(self, DN="", searchFilter="objectClass=*", scopeLevel=ldap3.SUBTREE, timeout=0):
        """ Базовый поиск и система запросов
            ### ДН
            DN: cn=Param ИЛИ cn=Param1,cn=Param2
            ### фильтр поиска
            searchFilter: (objectClass=*) 
            ### Таймаут запросов (в сек)
            timeout: 0"""
            
        components = self.ldapDomain.split('.')
        dn_components = [f"dc={component}" for component in components]
        formatted_dn = ','.join(dn_components)

        baseDN = DN + "," + formatted_dn if DN != "" else formatted_dn

        # Search in LDAP
        try:                                              
            searchResult = self.conn.search(search_base=baseDN, search_scope=scopeLevel, search_filter="("+searchFilter+")", attributes=ALL_ATTRIBUTES)
            sleep(timeout)

            for entry in self.conn.entries:
                yield "\nDN: " + str(entry.entry_dn)

                for attribute in entry.entry_attributes:
                    yield attribute + ": " + str(entry[attribute])
                                        
        except ValueError:
            yield "Colected all"
        except Exception as e:
            yield "Yield error: " + str(e)


    # writing to file 
    def toFile(self, folder="out/", timeout=1, yarafile=None, clear_old_files=True):
        """Функция для перенаправления ответов от AD сервера в файлы 
           ### Папка для сохранения
           folder: out/
           ### Таймаут запросов (в сек)
           timeout: 1
           ### Файл с правилами yara 
           yara.txt 
           ### Очистка старых файлов в папке
           clear_old_files: True"""
           
        if clear_old_files:
            removeFiles()
            
        if not os.path.exists(folder):
            os.makedirs(folder)

        if yarafile:
            rules = [line.strip() for line in yarafile.readlines()]
            yarafile.close()

            for rule in rules:
                for i in self.search(DN=rule, timeout=timeout):   
                    with open(os.path.join(folder, rule.replace("CN=", "").replace(",", "-")), 'a') as file:
                        file.write(i+"\n")

            sortFile()
        
        else:
            # по ONE_LEVEL создать файлы а по SUB_TREE заполнить файлы
            for i in self.search(scopeLevel=ldap3.LEVEL, timeout=timeout): # default to all AD treas
                main_cn = next((line.split(':', 1)[1].strip() for line in i.split('\n') if line.startswith("DN:")), None)
                if main_cn != None:
                    main_cn = main_cn.split(",DC")[0]
                    # print("wewe: ", main_cn)
                    for sub in self.search(DN=main_cn, timeout=timeout):
                        with open(os.path.join(folder, main_cn.replace("CN=", "").replace(",", "-")), 'a') as file:
                            file.write(sub+"\n")

            sortFile()
            
