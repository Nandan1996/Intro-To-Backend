import os
import re
from string import letters
import random
import hmac
import hashlib
import webapp2
import jinja2
from google.appengine.ext import db

#setting up jinja environment
template_dir = os.path.join(os.path.dirname('__file__'),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)

secret = 'ps.abzk1~nsndxa>sqb&li$094=!'
def hash_str(s):
    #return hashlib.md5(s).hexdigest()
    return hmac.new(secret,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

	def set_secure_cookie(self,name,val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			"%s=%s; path=/" %(name,cookie_val))
	def read_secure_cookie(self,name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self,user):
		self.set_secure_cookie('user_id',str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie','user_id=; path=/')

	#it is called by gae at first step
	def initialize(self,*a,**kw):
		webapp2.RequestHandler.initialize(self,*a,**kw)
		uid = self.read_secure_cookie('user_id')
		#checking whether user is alredy logged in
		self.user = uid and User.by_id(int(uid))


		
class MainPage(BlogHandler):
	def get(self):
		self.write('hello, udacity!')
		
#signup stuff's
#for signup validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EMAIl_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
	if USER_RE.match(username):
		return True
	else:
		return False
def valid_password(password):
	if PWD_RE.match(password):
		return True
	else:
		return False
def valid_email(email):
	if EMAIl_RE.match(email):
		return True
	else:
		return False
class Signup(BlogHandler):
	def get(self):
		self.render('signup.html')	
	def post(self):
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username=self.username,email = self.email)
		herror = False

		if not valid_username(self.username):
			params['uerror'] = "That wasn't a valid username."
			herror = True
		if not valid_password(self.password):
			params['perror'] = "That wasn't a valid password."
			herror = True
		if not self.password == verify:
			params['verror'] = "Your passwords didn't match."
			herror = True
		if not (self.email == "" or valid_email(self.email)):
			params['eerror'] = "That wasn't a valid email."
			herror = True

		if herror:
			self.render('signup.html',**params)
		else:
			self.done()				

	def done(self,username):
		raise NotImplementedError

class Unit2Signup(Signup):
	def done(self,username):
		self.redirect('/unit2/welcome?username='+self.username)
		
class Unit2Welcome(BlogHandler):
	def get(self):
		username = self.request.get('username')
		self.render('welcome.html',username = username)

#blog stuff's
def blog_key(name = "default"):
	return db.Key.from_path('blogs',name)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n','<br>')
		return render_str('post.html',p=self)

class BlogFront(BlogHandler):
	def get(self):
		posts = db.GqlQuery("select * from Post order by created desc limit 10")
		self.render('front.html',posts = posts)

class PostPage(BlogHandler):
	def get(self,post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		if not post:
			self.error('404')
			return
		else:
			self.render('permalink.html',post=post)
class NewPost(BlogHandler):
	def get(self):
		self.render('newpost.html')
	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')
		if subject and content:
			p = Post(parent = blog_key(),subject = subject, content = content)
			key = p.put()
			self.redirect('/blog/%s' %str(key.id()))
		else:
			error = 'subject and content, please!'
			self.render('newpost.html',subject = subject,content=content,error=error)
		
		
#user's stuff
def make_salt(length = 5):
	salt = ''.join(random.choice(letters) for x in xrange(length))
	return salt
def make_pw_hash(name,pw,salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s' % (salt,h)

def valid_pw(name, pw, h):
    salt = h.split(',')[0]
    new_hash = make_pw_hash(name,pw,salt)
    return new_hash == h

def users_key(group = 'default'):
	key = db.Key.from_path('users',group)
	return key

class User(db.Model):
	name = db.StringProperty(required = True)
	pwd_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls,uid):
		return User.get_by_id(uid,parent = users_key())

	@classmethod
	def by_name(cls,name):
		u = User.all().filter("name =", name).get()
		return u

	@classmethod
	def register(cls,name,password,email=None):
		pw_hash = make_pw_hash(name,password)
		return User(parent = users_key(),
		            name = name,
		            pwd_hash = pw_hash,
		            email = email)


class Register(Signup):
	def done(self):
		#Make sure user doesn't already exist
		u = User.by_name(self.username)
		if u:
			exists = "That user already exists."
			self.render("signup.html",exists = exists)
		else:
			user = User.register(name = self.username,
				                 password = self.password,
				                 email = self.email)
			user.put()
			self.login(user)
			self.redirect('/welcome')

class Login(BlogHandler):
	def get(self):
		self.render('login.html')
	def post(self):
		username = self.request.get('username')
		user = User.by_name(username)
		password = self.request.get('password')
		if user and valid_pw(username,password,user.pwd_hash):
			self.login(user)
			self.redirect('/welcome')
		else:
			self.render('login.html',username = username,error = 'Invalid login.')

class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/signup')
		

class Welcome(BlogHandler):
	def get(self):
		if self.user:		
			self.render("welcome.html",username = self.user.name)
		else:
			self.redirect('/signup')
		
		
app = webapp2.WSGIApplication([('/',MainPage),
	                           ('/blog/?',BlogFront),	                           
	                           ('/blog/([0-9]+)',PostPage),
	                           ('/blog/newpost',NewPost),
	                           ('/unit2/signup',Unit2Signup),
	                           ('/unit2/welcome',Unit2Welcome),
	                           ('/signup',Register),
	                           ('/welcome',Welcome),
	                           ('/login',Login),
	                           ('/logout',Logout)
	                           ],debug = True)


#nothing 