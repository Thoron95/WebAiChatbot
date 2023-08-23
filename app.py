from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
import openai
import json
import os
import configparser
import random
import string
import hashlib
import binascii
import shutil


def open_file(filepath):
    with open(filepath, 'r') as file:
        return file.read()


def write_to_json(filepath, content):
    with open(filepath, 'w') as file:
        file.write(content)


openai.api_key = open_file('openaiapikey.txt')
app = Flask(__name__, template_folder="./desktop_site")
app.config.from_pyfile('config.cfg')
app.config["SECRET_KEY"] = "a_very_secret_key"
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(100))
    password = db.Column(db.String(255))
    is_active = db.Column(db.Boolean)
    is_admin = db.Column(db.Boolean)


class UserPass:

    def __init__(self, user="", password=""):
        self.user = user
        self.password = password
        self.email = ""
        self.is_valid = False
        self.is_admin = False

    def hash_password(self):
        """Hash a password for storing."""
        os_urandom_static = b'\x92\xed\x01H\x9c\xaa\xcbx\xdceC\x87\x8f-\xf0l/\\\xaep\x8a\x8e\xear\xf4\xa7\xf2\xaey\x8e\x98\xf1Q\x10[b\xe3\xb5\xfd0\x7f\xe5\xcb\xe3m\x82dxd\x85+\xd0C\xd9mz9\x02\x81\x10'
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode("ascii")
        pwdhash = hashlib.pbkdf2_hmac("sha512", self.password.encode("utf-8"), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode("ascii")

    def verify_stored_password(self, stored_password: str, provided_password: str) -> bool:
        """Verify stored password against one provided by the user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac("sha512", provided_password.encode("utf-8"), salt.encode("ascii"), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode("ascii")
        return pwdhash == stored_password

    def login_user(self):
        user = User.query.filter(User.name == self.user).first()
        print(user)

        if user and self.verify_stored_password(stored_password=user.password, provided_password=self.password):
            return user
        else:
            self.user = None
            self.password = None
            return None

    def get_random_user_password(self):
        random_password = ""
        for i in range(5):
            random_password += random.choice(string.ascii_lowercase)
            random_password += random.choice(string.digits)
            random_password += random.choice(string.ascii_uppercase)
            random_password += random.choice(string.punctuation)
        self.password = random_password

    def get_user_info(self):
        db_user = User.query.filter(User.name == self.user).first()

        if not db_user:
            self.is_valid = False
            self.is_admin = False
            self.email = ""
        elif not db_user.is_active:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user.email
        else:
            self.is_valid = True
            self.is_admin = db_user.is_admin
            self.email = db_user.email


class Personas:
    """Take care of all the stuff with AI personas. Takes 'user' as argument(more with it to do later)"""

    def __init__(self, user, active_persona=None):
        super().__init__()
        self.user = user
        self.existing_personas = sorted(os.listdir(f"static/users/{self.user}/ai_personas"))
        # Set the first persona from the list as active by default(For now. Use last one used in future)
        self.avatars = self.get_avatars()
        if active_persona:
            self.active_persona = self.switch_persona(active_persona)
        else:
            if len(self.existing_personas) > 0:
                self.active_persona = self.switch_persona(self.existing_personas[0])
            else:
                self.active_persona = {
                    "name": None,
                    "personality": "",
                    "is_roleplay": False,
                    "avatar": None,
                    "conversation": None,
                    "archive": None
                }

    def create_persona(self, name: str, personality: str, avatar, is_roleplay):

        print(is_roleplay)
        try:
            os.mkdir(f"static/users/{self.user}/ai_personas/{name}")
        except FileExistsError:
            flash(f"Persona {name} already exist!")
            return url_for("add_persona")

        config = configparser.ConfigParser()
        config["GENERAL"] = {}
        config["GENERAL"]["name"] = name
        config["GENERAL"]["personality"] = personality
        config["GENERAL"]["is_roleplay"] = is_roleplay

        with open(f"./static/users/{self.user}/ai_personas/{name}/persona_config.cfg", "w") as file:
            config.write(file)

        if avatar:
            if avatar.filename.split(".")[-1] == "jpg":
                avatar.save(f"./static/users/{self.user}/ai_personas/{name}/avatar.jpg")
            elif avatar.filename.split(".")[-1] == "png":
                avatar.save(f"./static/users/{self.user}/ai_personas/{name}/avatar.png")

    def get_conversation(self, persona, purpose: str):
        """
        Load conversation from conversation.json as it is and return it. Returns list of dictionaries.
        If file is not found, return empty list.
        """
        try:
            with open(f"./static/users/{self.user}/ai_personas/{persona}/{purpose}.json", 'r') as file:
                return json.loads(file.read())
        except FileNotFoundError:
            print(f"{purpose.capitalize()} for {persona} not found. Returning empty list")
            return []

    def get_avatars(self):

        links_to_avatars = {}
        for persona in self.existing_personas:
            if os.path.exists(f"./static/users/{self.user}/ai_personas/{persona}/avatar.jpg"):
                links_to_avatars[persona] = f"users/{self.user}/ai_personas/{persona}/avatar.jpg"
            elif os.path.exists(f"./static/users/{self.user}/ai_personas/{persona}/avatar.png"):
                links_to_avatars[persona] = f"users/{self.user}/ai_personas/{persona}/avatar.png"
        return links_to_avatars

    def get_response(self, prompt: str):
        """
        Takes a prompt as argument, assigns it to a 'user' and append to a conversation.
        It then generates response using model 'gpt-3.5.turbo', append it to conversation
        and save an end state of a conversation to 'conversation.json' file.
        :param prompt: str; A message from a 'user'
        :return: None
        """

        """Create a 'system' info for chatGPT describing how it should behave."""
        if self.active_persona["is_roleplay"]:
            conversation = [{"role": "system",
                             "content": f"You are roleplaying as {self.active_persona['name']}. "
                                        f"{self.active_persona['personality']}"}]
        else:
            conversation = [{"role": "system",
                             "content": f"You are {self.active_persona['name']}. "
                                        f"{self.active_persona['personality']}"}]

        """Add current conversation and new user response to conversation."""
        conversation += self.active_persona["conversation"]
        conversation.append({"role": "user", "content": prompt})

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=conversation,
            temperature=0.7,
            max_tokens=750,
            top_p=0.9
        )
        conversation.append({"role": "assistant", "content": response["choices"][0]["message"]["content"]})

        """Check if new conversation is over length limit. Omit the first value in a list as 
        system call is not saved to 'conversation.json'."""
        conversation = self.token_saver(conversation=conversation[1:])
        # I somehow managed to completely erase my conversation and leave a file blank. Adding this for future safety
        if not conversation:
            conversation = self.active_persona["conversation"]
            raise Exception("Conversation got erased. Restoring last saved state...")
        else:
            self.active_persona["conversation"] = conversation
            with open(f"./static/users/{self.user}/ai_personas/{self.active_persona['name']}/conversation.json", 'w') as file:
                json.dump(conversation, file)

    def modify_persona(self, name: str, personality: str, avatar, is_roleplay) -> None:

        """
        Modify persona with provided information.
        """

        if name != self.active_persona["name"]:
            os.rename(f"./static/users/{self.user}/ai_personas/{self.active_persona['name']}",
                      f"./static/users/{self.user}/ai_personas/{name}")

            config = configparser.ConfigParser()
            config["GENERAL"] = {}
            config["GENERAL"]["name"] = name
            config["GENERAL"]["personality"] = personality if personality != "" else self.active_persona["personality"]
            config["GENERAL"]["is_roleplay"] = is_roleplay

            with open(f"./static/users/{self.user}/ai_personas/{name}/persona_config.cfg", "w") as file:
                config.write(file)

            if avatar:
                avatar.save(f"./static/users/{self.user}/ai_personas/{name}/avatar.jpg")

            self.active_persona = self.switch_persona(name)
        else:
            config = configparser.ConfigParser()
            config["GENERAL"] = {}
            config["GENERAL"]["name"] = self.active_persona["name"]
            config["GENERAL"]["personality"] = personality if personality != "" else self.active_persona["personality"]
            config["GENERAL"]["is_roleplay"] = is_roleplay

        with open(f"./static/users/{self.user}/ai_personas/{self.active_persona['name']}/persona_config.cfg",
                  "w") as file:
            config.write(file)

        if avatar:
            avatar.save(f"./static/users/{self.user}/ai_personas/{self.active_persona['name']}/avatar.jpg")

    def remove_persona(self, persona):

        # Look at this later, it got to be updated (unnecessary code)
        shutil.rmtree(f"./static/users/{self.user}/ai_personas/{persona}", ignore_errors=True)

    def switch_persona(self, persona):
        if persona in self.existing_personas:

            config = configparser.ConfigParser()
            config.read(f"./static/users/{self.user}/ai_personas/{persona}/persona_config.cfg")
            conversation = self.get_conversation(persona, "conversation")
            archive = self.get_conversation(persona, "archive")

            if os.path.exists(f"./static/users/{self.user}/ai_personas/{persona}/avatar.jpg"):
                avatar = f"users/{self.user}/ai_personas/{persona}/avatar.jpg"
            elif os.path.exists(f"./static/users/{self.user}/ai_personas/{persona}/avatar.png"):
                avatar = f"users/{self.user}/ai_personas/{persona}/avatar.png"
            else:
                avatar = False

            active_persona = {
                "name": str(config["GENERAL"]["name"]),
                "personality": str(config["GENERAL"]["personality"]),
                "is_roleplay": "True" in config["GENERAL"]["is_roleplay"],
                "avatar": avatar,
                "conversation": conversation,
                "archive": archive
            }

            return active_persona
        else:
            print(f"Invalid persona provided: {persona}")
            print(f"Valid personas for{self.user} are: {self.existing_personas}")

    def token_saver(self, conversation):

        count = 0
        limit = 3000

        """Count the length of conversation."""
        for call in conversation:
            to_string = list(call["content"].split())
            count += len(to_string)

        if count > limit:
            flash(f"Word count for {self.active_persona['name']} is: {count} out of limit of {limit}.")
            conversation_to_archive = conversation[:int(len(conversation) / 2)]
            current_archive = self.get_conversation(self.active_persona["name"], "archive")
            for cell in conversation_to_archive:
                current_archive.append(cell)
            with open(f"./static/users/{self.user}/ai_personas/{self.active_persona['name']}/archive.json", 'w') as f:
                json.dump(current_archive, f)
            del conversation[:int(len(conversation) / 2)]
            # print(f"Shortened conversation:\n{conversation}")
            return conversation
        else:
            return conversation


@app.route("/init")
def init():

    user = User()
    db.create_all()

    users = user.query.filter(user.is_admin == True, user.is_active == True).all()
    if len(users) > 0:
        return "<h1>App already initialized. Nothing to do.</h1>"
    else:
        user_pass = UserPass(user="Admin")
        user_pass.get_random_user_password()
        admin = User(id=1,
                     name=user_pass.user,
                     password=user_pass.hash_password(),
                     email="admin@nowhere.com",
                     is_active=True,
                     is_admin=True)
        db.session.add(admin)
        db.session.commit()
        os.mkdir(f"./static/users/{user_pass.user}")
        os.mkdir(f"./static/users/{user_pass.user}/ai_personas")

        return f"<h1>Admin account has been created with following password: {user_pass.password}</h1>"


@app.route("/")
def index():

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for("login"))

    personas = Personas(login.user)
    if personas.active_persona["name"] is None:
        flash("Looks like you have no AI personas. Let's create one!")
        return redirect(url_for("add_persona", login=login))
    else:
        return redirect(url_for("chat", active_persona=personas.active_persona["name"], login=login))


@app.route("/login", methods=["GET", "POST"])
def login():

    login = UserPass(session.get("user"))
    login.get_user_info()

    if request.method == "GET":
        return render_template("login.html", login=login)
    else:
        user_name = "" if "name" not in request.form else request.form["name"]
        user_pass = "" if "password" not in request.form else request.form["password"]

        log = UserPass(user_name, user_pass)
        login_record = log.login_user()

        if login_record:
            session["user"] = user_name
            flash(f"Login successful, welcome {user_name}")
            return redirect(url_for("index"))
        else:
            flash("Login failed, try again.")
            return render_template("login", login=login)


@app.route("/logout")
def logout():

    if "user" in session:
        session.pop("user", None)
        flash("You are logged out")
    return redirect(url_for("login"))


@app.route("/users")
def users():

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for("login"))

    users_list = User.query.all()
    return render_template("users.html", users_list=users_list, login=login)


@app.route("/user_status_change/<action>/<user_name>")
def user_status_change(action, user_name):

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for("login"))

    user = User.query.filter(User.name == user_name).first()

    if action == "active":
        if user.is_active:
            user.is_active = False
        elif not user.is_active:
            user.is_active = True
        db.session.commit()
    elif action == "admin":
        if user.is_admin:
            user.is_admin = False
        elif not user.is_admin:
            user.is_admin = True
        db.session.commit()

    return redirect(url_for("users", login=login))


@app.route("/edit_user/<user_name>", methods=["GET", "POST"])
def edit_user(user_name):

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for("login"))

    user = User.query.filter(User.name == user_name).all()

    if not user:
        flash(f"User {user_name} does not exist!")
        return redirect(url_for("users", login=login))
    if request.method == "GET":
        return render_template("edit_user.html", user=user, login=login)
    else:
        new_email = "" if "email" not in request.form else request.form["email"]
        new_password = "" if "user_pass" not in request.form else request.form["user_pass"]

        if new_email and new_email != user["email"]:
            user.email = new_email
            db.session.commit()
            flash("Email has ben changed!")

        if new_password:
            user_pass = UserPass(user_name, new_password)
            if user_pass.hash_password() != user.password:
                user.password = user_pass.hash_password()
                db.session.commit()
                flash("Password has ben changed!")

    return redirect(url_for("users", login=login))


@app.route("/user_delete/<user_name>")
def user_delete(user_name):

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for("login"))

    if user_name != session["user"]:
        user = User.query.filter(User.name == user_name).first()
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user_name} has been deleted!")
    else:
        flash("You cannot delete your own account!")

    return redirect(url_for("users", login=login))


@app.route("/new_user", methods=["GET", "POST"])
def new_user():

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for("login"))

    message = None
    user = {}

    if request.method == "GET":
        return render_template("new_user.html", user=user, login=login)
    else:
        user["user_name"] = "" if "user_name" not in request.form else request.form["user_name"]
        user["email"] = "" if "user_name" not in request.form else request.form["email"]
        user["user_pass"] = "" if "user_pass" not in request.form else request.form["user_pass"]

    name_check = User.query.filter(User.name == user["user_name"]).all()
    is_user_name_unique = True if len(name_check) == 0 else False

    email_check = User.query.filter(User.email == user["email"]).all()
    is_email_unique = True if len(email_check) == 0 else False

    if user["user_name"] == "":
        message = "Name cannot be empty!"
    elif user["email"] == "":
        message = "Email cannot be empty!"
    elif user["user_pass"] == "":
        message = "Password cannot be empty!"
    elif not is_user_name_unique:
        message = f"User with the name {user['user_name']} already exist!"
    elif not is_email_unique:
        message = f"The email {user['email']} is already associated with an account!"

    if not message:
        user_pass = UserPass(user["user_name"], user["user_pass"])

        user = User(name=user_pass.user,
                    password=user_pass.hash_password(),
                    email=user["email"],
                    is_active=True,
                    is_admin=False)
        db.session.add(user)
        db.session.commit()
        os.mkdir(f"./static/users/{user_pass.user}")
        os.mkdir(f"./static/users/{user_pass.user}/ai_personas")
        flash(f"User {user_pass.user} created.")
        return redirect(url_for("users", login=login))
    else:
        flash(message)
        return render_template("new_user.html", user=user, login=login)


@app.route("/<active_persona>", methods=["GET", "POST"])
def chat(active_persona=None):

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for("login"))

    if request.method == "GET":
        if not active_persona:
            personas = Personas(login.user)
        else:
            personas = Personas(login.user, active_persona=active_persona)
        return render_template("index.html", personas=personas, login=login)
    elif request.method == "POST":
        if not active_persona:
            personas = Personas(login.user)
        else:
            personas = Personas(login.user, active_persona=active_persona)

        if "prompt" in request.form:
            personas.get_response(request.form["prompt"])
        return render_template("index.html", personas=personas, login=login)


@app.route("/manage_personas", methods=["GET", "POST"])
def manage_personas():

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for("login"))

    personas = Personas(login.user)
    return render_template("manage_personas.html", personas=personas, login=login)


@app.route("/manage_personas/add_persona", methods=["GET", "POST"])
def add_persona():

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for("login"))

    if request.method == "GET":
        personas = Personas(login.user)
        return render_template("add_persona.html", personas=personas, login=login)
    elif request.method == "POST":

        personas = Personas(login.user)

        if "avatar" in request.files:
            avatar = request.files["avatar"]
        else:
            avatar = None

        personas.create_persona(name=request.form["name"],
                                personality=request.form["personality"],
                                avatar=avatar,
                                is_roleplay="True" if "is_roleplay" in request.form else "False")

        flash(f"Persona {request.form['name']} successfully created!")
        return redirect(url_for("manage_personas", login=login))


@app.route("/manage_personas/<persona>", methods=["GET", "POST"])
def modify_persona(persona):

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for("login"))

    if request.method == "GET":

        personas = Personas(login.user, active_persona=persona)
        return render_template("modify_persona.html", personas=personas, login=login)

    elif request.method == "POST":

        personas = Personas(login.user, active_persona=persona)

        if "avatar" in request.files:
            avatar = request.files["avatar"]
        else:
            avatar = None

        personas.modify_persona(name=request.form["name"],
                                personality=request.form["personality"],
                                avatar=avatar,
                                is_roleplay="True" if "is_roleplay" in request.form else "False")

        flash(f"Persona {request.form['name']} has been successfully modified!")
        return redirect(url_for("manage_personas", login=login))


@app.route("/manage_personas/remove_persona/<persona>", methods=["GET", "POST"])
def remove_persona(persona):

    login = UserPass(session.get("user"))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for("login"))

    personas = Personas(login.user, active_persona=persona)

    if request.method == "GET":
        return render_template("remove_persona.html", personas=personas, login=login)
    elif request.method == "POST":
        personas.remove_persona(persona)
        flash(f"Persona {persona} successfully removed!")
        return redirect(url_for("manage_personas", login=login))


if __name__ == "__main__":
    # app.run()
    # Use that version later after opening port
    app.run(host="192.168.1.10", port=5000)
