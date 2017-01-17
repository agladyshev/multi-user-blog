import os
import webapp2
import jinja2
import bcrypt
import re
import random
from string import letters
import hashlib
import hmac

from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


secret = 'QM8DcZ8ThA7*se9MIyqFCBbV8A3QTU5!4DgD508Cq268Th42'
#super_secret = '8SE1SL8Wror8I9F2$aV30j7s1e69!O7WE414k!iD!0Mh^0**'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_pw_hash(password):
    return bcrypt.hashpw(password, bcrypt.gensalt())


# def make_salt(length = 5):
#     return ''.join(random.choice(letters) for x in xrange(length))

# def make_pw_hash(pw, salt = None):
#     if not salt:
#         salt = make_salt()
#     h = hashlib.sha256(pw + salt).hexdigest()
#     return '%s,%s' % (salt, h)    


def valid_pw(password, hashed):
    return hashed == bcrypt.hashpw(password, hashed)


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))


    # def logout(self):

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# def blog_key(name = 'default'):
#     return db.Key.from_path('blogs', name)


class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("entry.html", blog=self)


class MainPage(Handler):

    def render_main(self, subject="", content="", error=""):

        blogs = db.GqlQuery(
            "SELECT * FROM Blog ORDER BY created DESC limit 10")
        # blogs = Blog.all().order('-created')
        self.render(
            "blog.html", blogs=blogs)

    def get(self):

        self.render_main()


class NewPost(Handler):

    def get(self):

        self.render("form.html")

    def post(self):

        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            b = Blog(subject=subject, content=content)
            b.put()
            blog_id = b.key().id()
            self.redirect("/%d" % blog_id)
        else:
            error = "We need both a subject and some text!"
            self.render(
                "form.html", subject=subject, content=content, error=error)


class PostPage(MainPage):

    def get(self, blog_id):
        """
        When you use " (\d+) ", it sends this number as a parameter
        (of type string) to the get or post methods from PermaLink
        """
        blog = Blog.get_by_id(int(blog_id))
        if not blog:
            self.error(404)
            return

        self.render("blog.html", blogs=[blog])


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, username):
        u = User.all().filter('username =', username).get()
        return u

    @classmethod
    def register(cls, username, password, email=None):
        pw_hash = make_pw_hash(password)
        return User(username=username,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u and valid_pw(password, u.pw_hash):
            return u


class Register(Handler):

    def get(self):

        self.render("signup.html")

    def post(self):

        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASS_RE = re.compile(r"^.{3,20}$")
        MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

        username_valid = USER_RE.match(self.username)
        password_valid = PASS_RE.match(self.password)
        email_valid = MAIL_RE.match(self.email)

        is_error = False

        params = dict(username=self.username, email=self.email)

        if not username_valid:
            is_error = True
            params['username_error'] = "Not a valid username!"

        if not password_valid:
            is_error = True
            params['password_error'] = "Not a valid password!"

        if self.password and self.verify != self.password:
            is_error = True
            params['verify_error'] = "Passwords don't match!"

        if self.email and not email_valid:
            is_error = True
            params['email_error'] = "Incorrect email format"

        if is_error:
            self.render("signup.html", **params)
        else:
            self.success()

    def success(self):
        #make sure user doesn't already exist
        u = User.by_name(self.username)
        if u:
            self.render("signup.html",
                        username_error = "User with that name already exists")
        else:
            u = User.register(username=self.username,
                 password=self.password,
                 email=self.email)
            u.put()
            self.login(u)
            self.redirect("/welcome")


class LoginPage(Handler):

    def get(self):

        self.render("login.html")

    def post(self):

        username = self.request.get("username")
        password = self.request.get("password")

        username_valid = User.gql(
            "WHERE username = :username", username=username).get()
        password_valid = User.gql(
            "WHERE username = :username AND password = :password", username=username, password=password).get()

        is_error = False

        params = dict(username=username)

        if not username_valid:
            is_error = True
            params['username_error'] = "There is no user with that name!"
        else:
            if not password_valid:
                is_error = True
                params['password_error'] = "Wrong password!"

        if is_error:
            self.render("login.html", **params)
        else:
            self.response.headers.add_header(
                'Set-Cookie', 'username = %s; Path=/' % str(username))
            self.redirect("/welcome")


class Logout(Handler):

    def get(self):
        self.response.headers.add_header(
            'Set-Cookie', 'username =; Path=/')
        self.redirect("/signup")


class WelcomePage(Handler):

    def get(self):
        #refers to initialize function in Handler
        if self.user:
            self.render("welcome.html", username=self.user.username)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', NewPost),
                               ('/(\d+)', PostPage),
                               ('/signup', Register),
                               ('/login', LoginPage),
                               ('/logout', Logout),
                               ('/welcome', WelcomePage)
                               ],
                              debug=True)
