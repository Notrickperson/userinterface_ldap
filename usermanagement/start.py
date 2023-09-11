from os import sched_setscheduler
from flask import Flask, render_template, url_for, request, flash, redirect
from flask_login.utils import confirm_login, login_required, logout_user
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from flask_login import login_user, UserMixin, current_user
import ldap.modlist as modlist
from flask_mail import Mail
import re
import ldap
from sshpubkeys.exceptions import MalformedDataError
import models
from sshpubkeys import SSHKey


app = Flask(__name__)
app.config['SECRET_KEY'] = "Thisisasecret!"
app.config['DEBUG'] = True
Bootstrap(app)

login_manager = LoginManager(app)

# users are saved in memory
users = {}

# required for password binds
session_users = {}

# new
lm = models.ldapManager()


class User(UserMixin):
    def __init__(self, username, data, role):
        self.username = username
        self.data = data
        self.role = role

    def __repr__(self):
        return self.username

    def get_id(self):
        return self.username

    def get_dn(self):
        return self.data['dn']

    def get_role(self):
        return self.role


@login_manager.user_loader
def load_user(id):
    if id in users:
        return users[id]
    return None


# used to split the  sshkeydata into individual keys
# returns modified data
# if a invalid key gets in, gives back 1
def sshkey_split(data):

    # split all sshkeys into a list
    sshkeys = data['sshPublicKey'].splitlines()

    newentry = {}

    for sshkey in sshkeys:

        # print("testing....")
        #print("Key:", sshkey)
        try:
            testedssh = SSHKey(sshkey, strict=True)
        except Exception as error:
            print(error)
            return 1

        except MalformedDataError as e:
            print(e)
            return 1
        try:
            testedssh.parse()
        except Exception as error:
            print(error)
            return 1

        newentry[sshkey] = testedssh.hash_md5()

        data['sshPublicKey'] = newentry

        return data

# changing ldapdata attribute names for better display
# adding and deleting entrys


def display_data(data):

    # copy old to new
    newdata = data.copy()

    d = sshkey_split(data)

    print(d)

    # delete entrys
    if 'dn' in newdata:
        del newdata['dn']

    if 'sn' in newdata:
        del newdata['sn']

    if 'givenName' in newdata:
        del newdata['givenName']

    if 'cn' in newdata:
        del newdata['cn']

    # addentrys
    if 'Name' not in newdata:
        if 'displayName' in newdata:
            newdata['Name'] = newdata['displayName']
            del newdata['displayName']
        else:
            newdata['Name'] = ''

    if 'Username' not in newdata:
        if 'uid' in newdata:
            newdata['Username'] = newdata['uid']
            del newdata['uid']
        else:
            newdata['Username'] = ''

    if 'Position' not in newdata:
        if 'title' in newdata:
            newdata['Position'] = newdata['title']
            del newdata['title']
        else:
            newdata['Position'] = ''

    if 'Email' not in newdata:
        if 'mail' in newdata:
            newdata['Email'] = newdata['mail']
            del newdata['mail']
        else:
            newdata['Email'] = ''

    if 'TelephoneNumber' not in newdata:
        if 'telephoneNumber' in newdata:
            newdata['TelephoneNumber'] = newdata['telephoneNumber']
            del newdata['telephoneNumber']
        else:
            newdata['TelephoneNumber'] = ''

    if 'Company' not in newdata:
        if 'o' in newdata:
            newdata['Company'] = newdata['o']
            del newdata['o']
        else:
            newdata['Company'] = ''

    if 'SSH Public Keys' not in newdata:
        if 'sshPublicKey' in newdata:
            newdata['SSH Public Keys'] = newdata['sshPublicKey']
            del newdata['sshPublicKey']
        else:
            newdata['SSH Public Keys'] = ''

    if 'Address' not in newdata:
        address = ""
        if 'street' in newdata:
            address += str(newdata['street'])
            del newdata['street']

        if 'postalCode' in newdata:
            address += ", "
            address += str(newdata['postalCode'])
            del newdata['postalCode']

        if 'l' in newdata:
            address += " "
            address += str(newdata['l'])
            del newdata['l']

            newdata['Address'] = address
        else:
            newdata['Street'] = ''

    # todo
    # if 'Adress' not in newdata:
    #    newdata['Adress'] = newdata['stre']
    #    del newdata['displayName']

    return newdata


@app.route('/', methods=['GET', 'POST'])
def home():

    confirm_login()

    if not current_user or current_user.is_anonymous:
        return redirect(url_for('login'))

    # admin
    if current_user.get_role() == 'admin':

        # gets all users
        data = lm.load_data_adm(['dn'])

        alluserdata = {}
        for entry in data:
            alluserdata[entry] = dict(lm.load_userdata_adm(entry))

        if request.method == 'POST':

            user = request.form['userbutton']
            # for loop check which button has been clicked and change value
            for entry in alluserdata:
                if user == entry:
                    userdata = alluserdata[entry]
                    return render_template("admin_home.html", data=data, alluserdata=alluserdata, userdata=userdata)

        return render_template("admin_home.html", data=data)

    # users
    else:
        rawdata = dict(lm.load_ldap_data(str(current_user),
                                         str(current_user.get_role()), ['dn']))

        data = display_data(rawdata)

    # telephoneNumber change
    if request.method == "POST":

        # TODO: Änderungen bei zwei feldern möglich machen (momrntain nur eins möglich)

        # user role tel change
        if 'TelephoneNumber' in request.form and request.form['TelephoneNumber'] != data['TelephoneNumber']:
            try:
                if 'telephoneNumber' in rawdata:
                    old = {'telephoneNumber': [data['TelephoneNumber']]}
                    if request.form['TelephoneNumber']:
                        n = request.form['TelephoneNumber'].encode("utf-8")
                    else:
                        n = 'empty'.encode("utf-8")

                    new = {'telephoneNumber': [n]}
                    # convert
                    ldif = modlist.modifyModlist(old, new)

                    # modify
                    lm.l.modify_s(rawdata['dn'], ldif)
                    # print("Telephonenumber changed for user:", data['cn'])
                    flash('You successfully modified your telephone number')

                # if telephonenumber needs to be newly added
                else:

                    number = request.form['TelephoneNumber'].encode("utf-8")
                    lm.l.modify_s(rawdata['dn'], [
                                  (0, 'telephoneNumber', number)])

                    flash('You successfully modified your telephone number')

            except ldap.LDAPError as error:
                print(error)
                print("Error modifying the telephone Number")

        # change title
        if 'Position' in request.form and request.form['Position'] != data['Position']:
            try:
                if 'title' in rawdata:
                    # print("rawdata",rawdata)
                    old = {'title': [rawdata['title']]}
                    if request.form['Position']:
                        n = request.form['Position'].encode("utf-8")
                    else:
                        n = 'empty'.encode("utf-8")

                    new = {'title': [n]}

                    # convert
                    ldif = modlist.modifyModlist(old, new)
                    # modify
                    lm.l.modify_s(rawdata['dn'], ldif)
                    print("Title changed for user:", rawdata['cn'])
                    flash('You successfully modified your title')
                    rawdata = dict(lm.load_ldap_data(str(current_user),
                                                     str(current_user.get_role()), ['dn']))

                    data = display_data(rawdata)
                    return render_template("home.html", data=data)
                else:
                    # if position needs to be added
                    position = request.form['Position'].encode("utf-8")
                    lm.l.modify_s(rawdata['dn'], [(0, 'title', position)])
                    rawdata = dict(lm.load_ldap_data(str(current_user),
                                                     str(current_user.get_role()), ['dn']))

                    data = display_data(rawdata)

                    flash('You successfully modified your Position')
                    return render_template("home.html", data=data)

            except ldap.LDAPError as error:
                print(error)
                print("Error modifying the title")

        rawdata = dict(lm.load_ldap_data(str(current_user),
                                         str(current_user.get_role()), ['dn']))

        data = display_data(rawdata)
        return render_template("home.html", data=data)

    return render_template("home.html", data=data)


@app.route('/login', methods=['GET', 'POST'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        print(username)
        print(password)
    # catch empty fields
        if username == "" or password == "":
            error = "Please enter valid credentials"
            return render_template("login.html", error=error)

        # load ldap data
        try:

            if username == 'admin':
                response = lm.bind(username, password, 'admin')

            else:
                response = lm.bind(username, password, 'user')

               # print("RESPONSE",response)

            # Error handling
            if response == 1:
                error = "Wrong Credentials"
                return render_template("login.html", error=error)

            # wenn sich admin einloggt
            if username == 'admin':
                user = User(username, response, 'admin')

            else:

                username = response
                # replace uid with cn
                # create new session user
                user = User(username, [], 'user')

                login_user(user)

                # uadd session user
                session_users[username] = password

                # save user
                users[username] = user
                current_user.data = []

        except ldap.LDAPError as error:
            print(error)
            error = "Wrong Credentials"
            return render_template("login.html", error=error)

        return redirect("/")

    return render_template("login.html")


@login_required
@app.route('/logout')
def logout():
    if session_users:
        session_users.pop(str(current_user))

    if current_user and users:
        users.pop(str(current_user))

    response = logout_user()
    return redirect('/')


def password_check(password):
    """
    Returns a dict indicating the wrong criteria
    TODO for future: updating method to current ppolicy
    """

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(
        r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not (
        length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error,
    }


@login_required
@app.route('/password', methods=['GET', 'POST'])
def password():

    data = dict(lm.load_ldap_data(str(current_user), current_user.get_role()))

    if not current_user or current_user.is_anonymous:
        return redirect("/")

    if request.method == 'POST':
        error = ""

        current_pw = request.form['current_pw']
        new_pw = request.form['password1']

        # check if current pw is correct
        if request.form['current_pw'] != session_users.get(str(current_user)):
            error = "Wrong current password"
            return render_template("password.html", error=error)

        # Precheck that current pw cant be the same as old pw
        if request.form['current_pw'] == request.form['password1']:
            error = "Your new password can't be the same as your previous password"
            return render_template("password.html", bind_error=error)

        # check if password is strong enough
        pwcheck = password_check(request.form["password1"])

        if pwcheck["password_ok"] == True:
            # pw change in ldap

            lm.l.passwd_s(data['dn'], current_pw, new_pw)

            # change pw in sessionusers
            session_users[str(current_user)] = new_pw

            flash('You successfully changed your password')
            return redirect("/")

        else:

            if pwcheck['length_error'] == True:
                error += "Password is to short;"
            if pwcheck['digit_error'] == True:
                error += "Password needs to contain a number;"
            if pwcheck['uppercase_error'] == True:
                error += "Password needs to contain a uppercase letter;"
            if pwcheck['symbol_error'] == True:
                error += "Password needs to contain a symbol;"

            return render_template("password.html", error=error)

    return render_template("password.html")


@login_required
@app.route('/ssh', methods=['GET', 'POST'])
def ssh():
    if not current_user or current_user.is_anonymous:
        return redirect("/")

    data = dict(lm.load_ldap_data(str(current_user), current_user.get_role()))

    ssh = data['sshPublicKey']
    # print("SSH:",ssh)

    if request.method == 'POST':

        ssh = data['sshPublicKey']

        newssh = request.form['ssh']

        keylist = newssh.splitlines()

        counter = 1
        for key in keylist:
            print(counter, key)
            # test validity of ssh key
            try:
                testedssh = SSHKey(key, strict=True)

            except Exception as error:
                print(error)
                bind_error = "Following Key is invalid: " + \
                    str(counter) + "( " + str(error) + ")"
                return render_template("ssh.html", bind_error=bind_error, ssh=ssh)

            try:
                testedssh.parse()
            except Exception as error:
                print(error)
                bind_error = "Following Key is invalid: " + \
                    str(counter) + "( " + str(error) + ")"
                return render_template("ssh.html", bind_error=bind_error, ssh=ssh)
            counter += 1

        try:
            old = {'sshPublicKey': [ssh]}
            n = newssh.encode("utf-8")
            new = {'sshPublicKey': [n.strip()]}
            # convert
            ldif = modlist.modifyModlist(old, new)

            # modify
            lm.l.modify_s(data['dn'], ldif)

        except ldap.LDAPError as error:
            print(error)
            bind_error = "Error modifying the SSH-Keys"
            return render_template("ssh.html", bind_error=bind_error, ssh=ssh)

        flash('You successfully modified your SSH-Keys')
        return redirect("/")

    return render_template(("ssh.html"), ssh=ssh)


@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():

    if request.method == 'POST':

        message = "If your email is registered we will send you an email to you."

        # TODO: klaeren wer eine mail wohin sendet (emailserver) und ob es automatisiert werden soll oder ob es sinn macht es manuell zu erledigen
        # email = request.method['email']
        # msg = Message("Hello, following account needs an password reset:"+email, sender="ldapusermanagement@example.com",recipients=["admin@example.de"])

        return render_template("password_reset.html", message=message)

    return render_template("password_reset.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0")
