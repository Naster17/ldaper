# Установка 
sudo apt install python3-ldap3
python main.py --help 

# NTLM
python main.py -H ldap://192.168.1.103 -D ldap.domain.local -U Admin -P user@1234 -at NTLM -d "cn=Computers" 
# Новый -D
python main.py -H ldap://192.168.1.103 -D ldap.domain.local -U Admin -P user@1234 -tf -t 1
# Анон
python main.py -H ldap://192.168.1.103 -D ldap.domain.local -at ANONYMOUS  



# Автор
Вся документация теперь русифицирована для простоты чтения.
ldaputils.py улучшен и может быть импортирован в другие скрипты 
это упрощает оставленные в нём комментарии и описания функций для простоты использования.


# Об использование
## Подержка разных синтаксисов (', ", )
python main.py -H ldap://192.168.1.103 -D dc=ldap,dc=domain,dc=local -U Admin -P user@1234
python main.py -H "ldap://192.168.1.103" -D "dc=ldap,dc=domain,dc=local" -U "Admin" -P "user@1234"
python main.py -H 'ldap://192.168.1.103' -D "dc=ldap,dc=domain,dc=local" -U Admin -P "user@1234"


## Базовый с полной поддержкой разных протоколов и портов ldap, ldaps и все возможные
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local
                  ldap://192.168.1.101:389
                  ldaps://192.168.1.101

## Поддержка таймаутов в запросах (в секундах)
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U Admin -P user@1234 -t 2

## Интеграция с proxychains[4] и по идеи с похожими программами 
 proxychains4 python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U Admin -P user@1234 -t 2
### Тестировано с proxychains4 и http, https прокси, но так же должно работат с другими видами прокси

## можно вернуть абсолютно всю информацию с AD одиним запросом
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U Admin -P user@1234

## конкретный поиск и многоуровневый поиск
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U Admin -P user@1234 -d "cn=Users"
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U Admin -P user@1234 -d "cn=Admin,cn=Users"

## Пустой пароль | Без использование пароля
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U "" -P ""
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local 
### Так же 
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U "Admin" -P ""
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U "Admin"


# Запись в файлы (создаст папку out/ в которую запишет все данные из AD веток и 
                  по умолчанию отсортирует только Computers на operationSystem
                  Так же исклюит мусорный поиск. Разницу поиска можно увидеть в 
                  ONE_LEVEL нормальный и SUB_TREE полный в большенстве мусорный поиск) 
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U "Admin" -P "admin" -tf


# Мульти сортировка
## Полезно для сортировок которые не включены в скрипт
### Пример где на выходе получим файлы с названиями операцыоных систем которые указаны в полях operatingSystem
### То есть при совпадение в других блоках ответов AD по operatingSystem он будет добовлятся в уже существуюший файл, а не создавать новый
### Тем самым мы повторим ту же сортировку по ОС что и скрипт, только вручную
 python main.py --sfile Computers --sfolder out/ --sword operatingSystem

## Вот несколько примеров для понимания сортировки (Пользователей по имени)
 python main.py --sfile Users --sfolder out/ --sword name
## Система по имени
 python main.py --sfile System --sfolder out/ --sword name
## Вообщем можно использовать на все случаи в сортировке


# Кастомный поиск или же yara
## Сделано в концепции по обходу детекта (в большей часте вторженния в AD мониторятся обращениям к 
определёным частям AD) для этого и создано кастомизированое указание веток и суд веток
## Разницу в ветках можно увидеть в файлах BASE, ONE_LEVEL, SUB_TREE
Info:
  yara.txt пример файла с правилами какие ветки будут затрагиватся для дампа
  если не указано использования yara тогда будут затронуты абсолютно все ветки AD 
  это сделано чтобы улучшить ручные методы анти-обноружения в связи с спецификой протокола ldap 

### Оба варианта запишут файлы
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U Admin -P user@1234 -tf --yara yara.txt 
python main.py -H ldap://192.168.1.101 -D dc=ldap,dc=domain,dc=local -U Admin -P user@1234 --yara yara.txt 