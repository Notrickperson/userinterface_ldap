import ldap
import re

# Class die verschiedene Ldap funktionen uebernimmt

### TODO


class ldapManager():
    l = None

    def __init__(self, *server):
        # diffrent server
        if server:
            self.l = ldap.initialize('ldaps://%s' % server[0])
            print("Initialized ldap server:", server[0])

        else:
            #ldaps change in url
            server = 'ldap.forumsys.com'
            self.l = ldap.initialize('ldap://%s' % server)
            print(self.l)
            print("Initialized ldap server:", server)

    # returns the cn of a user after sucessfull bind
    # returns 0 if it wasnt sucessfull

    def bind(self, username, password, role):

        if role == 'admin':
            self.l.simple_bind_s('cn=read-only-admin,dc=example,dc=com', password)
            print("Bind user:", username)
        if role == 'user':

            try:
                # login as admin
                self.l.simple_bind_s(
                    'cn=read-only-admin,dc=example,dc=com', 'password')

                # search for uid
                search_filter = '(objectclass=*)'
                search = self.l.search_s(
                    'cn=read-only-admin,dc=example,dc=com', ldap.SCOPE_SUBTREE, search_filter, ['uid'])

                print("RESULT", dict(search))

                dn = ""

                # extracting the fititng uid out of the results
                for ele in search:
                    values = ele[1]
                    if 'uid' in values:
                        uid = values['uid'][0].decode("utf-8")

                        if uid == username:
                            dn = ele[0]

                self.l.simple_bind_s(dn, password)
                print("Bind user:", username)

                # extract cn out of dn
                lis = dn.split(",")
                cn = lis[0][3:]

                return cn

            except Exception as e:
                print("Excepion:", e)

            return 1

    # used for the login

    def load_ldap_data(self, username, role, *filter):
        search_filter = '(objectclass=*)'

        try:
            search_filter = '(&(objectclass=person)(cn=%s))' % username

            dn = 'cn=%s,ou=people,dc=example,dc=de' % username
            [result] = self.l.search_s(dn, ldap.SCOPE_SUBTREE, search_filter)

            data = result[1]

            # convert bit string data to string
            for key in data:
                value = data.get(key)[0]
                data[key] = value.decode("utf-8")

            # add dn to data, delete unnecessary data
            if role == 'admin':
                data['dn'] = 'cn=admin,dc=example,dc=de'
            else:
                dn = 'cn=%s,ou=people,dc=example,dc=de' % username
                data['dn'] = dn

            if 'objectClass' in data:
                del data["objectClass"]

            if 'userPassword' in data:
                del data['userPassword']

            old = data

            # reverse list, because of style
            data = []
            for key in old:
                data.append((key, old[key]))
            data.reverse()

        except ldap.LDAPError as error:
            print("Error with loading data from Ldap -server:", error)
            return 1

        return data

    def load_data_adm(self, filter):
        search_filter = '(objectclass=*)'

        try:
            if filter:
                search = self.l.search_s(
                    'ou=people,dc=example,dc=de', ldap.SCOPE_SUBTREE, search_filter, filter)
                data = dict(search)

                beginning = 'cn='
                end = ','

                # extract cn out of dn
                for key in data:
                    lis = key.split(",")
                    data[key] = lis[0][3:]

                # reverse key and data
                reversed_dictionary = {
                    value: key for (key, value) in data.items()}

                # del people dn
                if 'people' in reversed_dictionary:
                    del reversed_dictionary['people']

                print("DATA:", reversed_dictionary)
                return reversed_dictionary

            search = self.l.search_s(
                'cn=admin,dc=example,dc=de', ldap.SCOPE_SUBTREE, search_filter)
            result = search[0]

        except ldap.LDAPError as error:
            print("Error with loading data from Ldap -server:", error)
            return 1

    # load data from a user
    def load_userdata_adm(self, username):

        try:
            search_filter = '(&(objectclass=person)(cn=%s))' % username
            dn = 'cn=%s,ou=people,dc=example,dc=de' % username
            [result] = self.l.search_s(dn, ldap.SCOPE_SUBTREE, search_filter)

            data = result[1]

            # convert bit string data to string
            for key in data:
                value = data.get(key)[0]
                data[key] = value.decode("utf-8")

            # add dn to data, delete unnecessary data
            # if role == 'admin':
            #    data['dn'] = 'cn=admin,dc=example,dc=de'
            # else:
            dn = 'cn=%s,ou=people,dc=example,dc=de' % username
            data['dn'] = dn

            if 'objectClass' in data:
                del data["objectClass"]

            if 'userPassword' in data:
                del data['userPassword']

            # print("DATA:", data)
            old = data

            # reverse list, because of style
            data = []
            for key in old:
                data.append((key, old[key]))
            data.reverse()

        except ldap.LDAPError as error:
            print("Error with loading data from Ldap -server:", error)
            return 1

        return data
