#!/usr/bin/env python

import datetime
import geoip
import os

from flask import Flask, request, render_template, redirect, url_for
from flask.ext.login import LoginManager, UserMixin, user_logged_in, login_user, logout_user, login_required, current_user
from flask.ext.sqlalchemy import SQLAlchemy
from werkzeug import generate_password_hash, check_password_hash
from wtforms import Form, TextField, TextAreaField, SubmitField, validators, ValidationError, PasswordField

from utils import getRandomIP


class Config(object):
	DEBUG = True
	SECRET_KEY = "secret"
	SQLALCHEMY_DATABASE_URI = "postgresql://localhost/logintrackingexample"


app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
loginManager = LoginManager(app)


# flask login config
loginManager.login_view = "loginPage"

@loginManager.user_loader
def loadUser(userID):
	return User.query.filter_by(userID=int(userID)).first()


# models

class User(db.Model, UserMixin):
	__tablename__ = "users"

	userID = db.Column(db.Integer, primary_key=True)
	emailAddress = db.Column(db.String, nullable=False, unique=True)
	password = db.Column(db.String)

	logins = db.relationship("Login", backref="user", order_by="Login.happened")


	def __init__(self, userID=None, emailAddress=None, password=None):
		self.userID = userID
		self.emailAddress = emailAddress
		self.password = password

	def setPassword(self, password):
		"""
		Saves a hash of the password string to the object.
		"""
		self.password = generate_password_hash(password)

	def checkPassword(self, password):
		"""
		Returns True if the password matches the user's
		password; False otherwise.
		"""
		return check_password_hash(self.password, password)

	def is_authenticated(self):
		"""
		For flask-login. Returns True if the user is
		authenticated; False otherwise.
		See: https://flask-login.readthedocs.org/en/latest/
		"""
		return True

	def is_active(self):
		"""
		For flask-login. Returns True if the user is active;
		False otherwise.
		See: https://flask-login.readthedocs.org/en/latest/
		"""
		return True

	def is_anonymous(self):
		"""
		For flask-login. We don't allow anonymous access
		for this app.
		"""
		return False

	def get_id(self):
		"""
		For flask-login. Returns unicode of the unique user ID.
		"""
		return unicode(self.userID)

	def __repr__(self):
		return "<User %d>" %self.userID


class Country(db.Model):
	__tablename__ = "countries"

	countryID = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String, nullable=False)
	code = db.Column(db.String(3))

	def __init__(self, countryID=None, name=None, code=None):
		self.countryID = countryID
		self.name = name
		self.code = code

	def __repr__(self):
		return "<Country %d>" %self.countryID


class Login(db.Model):
	__tablename__ = "logins"

	loginID = db.Column(db.Integer, primary_key=True)
	userID = db.Column(db.ForeignKey("users.userID"), nullable=False)
	ip = db.Column(db.Text, nullable=False)
	countryID = db.Column(db.ForeignKey("countries.countryID"))
	longitude = db.Column(db.Float)
	latitude = db.Column(db.Float)
	happened = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())

	country = db.relationship("Country")

	def __init__(self, loginID=None, userID=None, ip=None, countryID=None, longitude=None, latitude=None, happened=None):
		self.loginID = loginID
		self.userID = userID
		self.ip = ip
		self.countryID = countryID
		self.longitude = longitude
		self.latitude = latitude
		self.happened = happened

	def __repr__(self):
		return "<Login %d>" %self.loginID


# forms

class RegistrationForm(Form):
	emailAddress = TextField("Email Address",  [validators.Required("Please enter your email address."), validators.Email("Please enter a valid email address.")])
	password = PasswordField('Password', [validators.Required("Please enter a password.")])
	submit = SubmitField("Create account")

	def validate(self):
		if not Form.validate(self):
			return False

		user = User.query.filter_by(emailAddress=self.emailAddress.data.lower()).first()

		if user:
			self.emailAddress.errors.append("Email address already taken")
			return False
		else:
			return True


class LoginForm(Form):
	emailAddress = TextField("Email Address", [validators.Required("Please enter your email address.")])
	password = PasswordField("Password", [validators.Required("Please enter your password.")])
	loginButton = SubmitField("Login")

	def validate(self):
		if not Form.validate(self):
			return False

		user = User.query.filter_by(emailAddress=self.emailAddress.data.lower()).first()

		if not user:
			self.emailAddress.errors.append("No account found.")
			return False

		if not user.checkPassword(self.password.data):
			self.password.errors.append("Password incorrect.")
			return False

		return user


# views

@app.route("/", methods=["GET", "POST"])
def loginPage():
	form = LoginForm(request.form)
	
	if request.method == "POST":
		user = form.validate()
		
		if not user:
			return render_template("login.html", form=form)
				
		login_user(user)
		nextURL = request.args.get("next")
		return redirect(nextURL or url_for("home"))

	return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
	form = RegistrationForm(request.form)

	if request.method == "POST":
		if not form.validate():
			return render_template("register.html", form=form)
		
		else:
			newUser = User(emailAddress=form.emailAddress.data)
			newUser.setPassword(form.password.data)
			db.session.add(newUser)
			db.session.commit()

			return render_template("registered.html")
 
	elif request.method == "GET":
		return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect(url_for("loginPage"))


@app.route("/home")
@login_required
def home():
	return render_template("home.html")


# signals

def saveLoginEvent(app, user):

	#FIXME use real IP in production
	#ip = request.remote_addr
	ip = getRandomIP()

	login = Login(userID=user.userID, ip=ip)
	match = geoip.geolite2.lookup(ip)

	if match:
		country = Country.query.filter_by(code=match.country).first()

		if country:
			login.countryID = country.countryID

		if match.location:
			login.latitude, login.longitude = match.location
	
	db.session.add(login)
	db.session.commit()

user_logged_in.connect(saveLoginEvent)


if __name__ == "__main__":
	app.run()
