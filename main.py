#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
from string import letters

import webapp2
import jinja2


from google.appengine.api import users
from google.appengine.ext import ndb
from google.appengine.ext.webapp import template

import hashlib
import hmac
import random
import string

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = "nooneknows"

def make_secure_val(val):
	return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val  = secure_val.split('|')[0]
	return secure_val == make_secure_val(val)

def set_cookie(handler, name, value):
	handler.response.headers.add_header("set-cookie", "%s=%s; path=/" %
										(str(name), str(value)))

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t= jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class Signupform(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		firstname = self.request.get('form-first-name')
		lastname = self.request.get('form-last-name')
		email = self.request.get('form-email')
		district = self.request.get('district')
		city = self.request.get('city')
		college = self.request.get('college')
		year = self.request.get('year')
		password = self.request.get('form-password')
		verify = self.request.get('form-verify')

		params = dict(firstname = firstname, email = email)

		if not valid_username(firstname):
			params['error_firstname'] = "That is not a valid firstname"
			have_error = True

		if not valid_username(lastname):
			params['error_lastname'] = "That is not a valid lastname"
			have_error = True

		if not year:
			params['error_year'] = "enter your graduation year"
			have_error = True

		if not valid_password(password):
			params['error_password'] = "That wasn't a valid password"
			have_error = True
		elif password != verify:
			params['error_verify'] = "passwords didn't match"

		if not valid_email(email):
			params['error_email'] = "That's not a valid email"
			have_error = True

		if have_error:
			self.render("signup.html", **params)
		else:
			a = InsertData(firstname = firstname, lastname = lastname, password = password,
			 email = email, college = college, district = district, city = city, year = year)
			a.put()
			self.redirect("/")



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)



class MainHandler(Handler):
    def get(self):
        self.render("signin.html")

    def post(self):
    	email = self.request.get('form-username')
    	password = self.request.get('form-password')
    	params = {}
    	result = InsertData()
    	results = result.query()
    	flag = False
    	for r in results:
    		if r.email == email:
    			flag = True
    			if r.password != password:
    				flag = False
    				params['error_password'] = "your password is incorrect"
    			else:
    				set_cookie(self, "email", make_secure_val(email))
    				self.redirect("/welcome")
    	if not flag:
    		self.render("signin.html", **params)


class InsertData(ndb.Model):
	firstname = ndb.StringProperty(required = True)
	lastname = ndb.StringProperty(required = True)
	password = ndb.StringProperty(required = True)
	email = ndb.StringProperty(required = True)
	district = ndb.StringProperty(required = True)
	city = ndb.StringProperty(required = True)
	college = ndb.StringProperty(required = True)
	year = ndb.StringProperty(required = True)  

class Art(ndb.Model):
	username = ndb.StringProperty(required = True)
	title = ndb.StringProperty(required = True)
	art = ndb.TextProperty(required = True)
	created = ndb.DateTimeProperty(auto_now_add = True)

class Logout(webapp2.RequestHandler):
	def get(self):
		set_cookie(self, "email", "")
		self.redirect("/")

class Welcome(Handler):
	def get(self):
		c = self.request.cookies.get("email")
		if c:
			if check_secure_val(c):
				val  = c.split('|')[0]
				result = InsertData()
				results = result.query()
				res = results.filter(InsertData.email == val)
				for r in res:
					val2 = r.college
					val3 = r.firstname
				clists = InsertData()
				clist = clists.query()
				collegemembers = clist.filter(InsertData.college == val2)

				# events = Art()
				# event = events.query().order(-Art.created)
				self.render("welcome.html",val3 = val3, collegemembers = collegemembers)
			else:
				self.redirect("/")
		else:
			self.redirect("/signup")

	def post(self):
		c = self.request.cookies.get("email")
		if check_secure_val(c):
			val = c.split('|')[0]
			result = InsertData()
			results =result.query()
			res = results.filter(InsertData.email == val)
			for r in res:
				val3 = r.firstname
				val4 = r.college
			title = self.request.get("title")
			art = self.request.get("art")
			if title and art:
				a = Art(username = val3, title = title, art = art)
				a.put()
				self.redirect("/events")
			else:
				error = "Enter title and event"
				self.render("welcome.html",error = error)
		else:
			self.redirect("/")

class Events(Handler):
	def get(self):
		c = self.request.cookies.get("email")
		if check_secure_val(c):
			events = Art()
			event = events.query().order(-Art.created)
			self.render("table.html",event = event)
		else:
			self.redirect("/")



app = webapp2.WSGIApplication([('/', MainHandler),
								('/signup',Signupform),
								('/welcome',Welcome),
								('/logout',Logout),
								('/events',Events)], debug=True)
