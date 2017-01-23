import os
import webapp2
import jinja2
import re
import random
import logging
import hmac
import json
from string import letters
from pybcrypt import bcrypt

from google.appengine.ext import ndb


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def get_new_comment(comment_key):
    comment = ndb.Key(urlsafe=comment_key)
    return comment.get()

jinja_env.globals['get_new_comment'] = get_new_comment


secret = 'QM8DcZ8ThA7*se9MIyqFCBbV8A3QTU5!4DgD508Cq268Th42'


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
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')

        self.user = uid and User.by_id(int(uid))

    def is_owner(self, blog):
        # check if logged in user is an author of a blog
        if self.user and blog.key.parent() == self.user.key:
            return True


def users_key(group='default'):
    return ndb.Key('users', group)


def get_user_key(user_id):

    return ndb.Key(User, user_id, parent=users_key())


class User(ndb.Model):
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.query().filter(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, password, email=None):
        pw_hash = make_pw_hash(password)

        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, password):
        u = cls.by_name(name)
        if u and valid_pw(password, u.pw_hash):
            return u


# def blog_key(name = 'default'):
#     return ndb.Key.from_path('blogs', name)


class Blog(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    #author = ndb.ReferenceProperty(User, required=True)

    def get_comments(self):
        blog_key = self.key
        c = Comment.by_blog_key(blog_key)
        return c

    def get_likes(self):
        blog_key = self.key
        l = Like.by_blog_key(blog_key)
        return l.count()

    def is_owner(self, current_user=None):
        if current_user:
            return self.key.parent() == current_user.key

    def render(self, current_user=None):
        self._render_text = self.content.replace('\n', '<br>')
        comments = self.get_comments()
        likes = self.get_likes()

        return render_str("entry.html",
                          blog=self,
                          comments=comments,
                          likes=likes,
                          current_user=current_user)

    @classmethod
    def by_id(cls, blog_id, user_id):
        parent = get_user_key(user_id)
        return cls.get_by_id(blog_id, parent=parent)


class Comment(ndb.Model):
    # author = ndb.ReferenceProperty(User, required=True)
    blog = ndb.KeyProperty(kind=Blog, required=True)
    content = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

    def is_owner(self, current_user=None):
        if current_user:
            return self.key.parent() == current_user.key

    def render(self, current_user=None):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html",
                          comment=self,
                          current_user=current_user)

    @classmethod
    def by_blog_key(cls, blog_key):
        comments = cls.query().filter(
            Comment.blog == blog_key).order(Comment.created)
        return comments


class Like(ndb.Model):
    blog = ndb.KeyProperty(kind=Blog, required=True)
    # author = ndb.ReferenceProperty(User, required=True)

    # def is_owner(self, current_user=None):
    #     if current_user:
    #         return self.key.parent() == current_user.key

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_blog_key(cls, blog_key):
        # needs work
        likes = cls.query().filter(Like.blog == blog_key)
        return likes

    @classmethod
    def get_user_like(cls, user_key, blog_key):
        # rewrite for parent key
        # check if user has liked blog already, return object or null
        return cls.query(ancestor=user_key).filter(Like.blog == blog_key).get()


class MainPage(Handler):

    def render_main(self):

        # blogs = ndb.GqlQuery(
        #     "SELECT * FROM Blog ORDER BY created DESC limit 10")
        blogs = Blog.query().order(-Blog.created)

        self.render(
            "blog.html", blogs=blogs, current_user=self.user)

    def get(self):

        self.render_main()

    # def post(self):
    #     comment = self.request.get("comment")
    #     blog_key = self.request.get("blog_key")
    #     blog_key = ndb.Key(urlsafe=blog_key)
    #     user_key = get_user_key(self.user.key.id())
    #     if comment:
    #         c = Comment(content=comment, parent=user_key, blog=blog_key)
    #         c.put()
    #     else:
    #         like = Like.get_user_like(
    #             user_key=self.user.key, blog_key=blog_key)
    #         if like:
    #             like.key.delete()
    #         else:
    #             l = Like(parent=user_key, blog=blog_key)
    #             l.put()
    #     self.render_main()


# class PageNum(MainPage):

#     def render_main(self, num):
#         self.render_main()


class NewPost(Handler):

    def get(self):

        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):

        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:

            # post_id = self.create_post_id(subject)

            user_key = get_user_key(self.user.key.id())

            b = Blog(subject=subject, content=content, parent=user_key)
            b.put()
            author = self.user.name
            blog_id = b.key.id()
            self.redirect("/%s/%d" % (author, blog_id))
        else:
            error = "We need both a subject and some text!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)

    # def create_post_id(self, subject):
    #     post_id = str(subject)
    #     post_id = post_id.lowercase().strip()
    #     post_id = subject.replace("","-")
    #     return post_id


class PostPage(MainPage):

    def get(self, author, blog_id):
        """
        When you use " (\d+) ", app sends this number as a parameter
        (of type string) to the get or post methods
        """

        u = User.by_name(author)
        user_id = u.key.id()
        blog = Blog.by_id(int(blog_id), int(user_id))
        if not blog:
            self.error(404)
            return
        self.render("postpage.html", blog=blog, current_user=self.user)

    # def post(self, author, blog_id):

    #     comment = self.request.get("comment")
    #     blog_key = self.request.get("blog_key")
    #     blog_key = ndb.Key(urlsafe=blog_key)
    #     user_key = get_user_key(self.user.key.id())
    #     blog = blog_key.get()
    #     if comment:
    #         c = Comment(content=comment, parent=user_key, blog=blog_key)
    #         c.put()
    #     else:
    #         like = Like.get_user_like(
    #             user_key=self.user.key, blog_key=blog_key)
    #         if like:
    #             like.key.delete()
    #         else:
    #             l = Like(parent=user_key, blog=blog_key)
    #             l.put()

    #     self.render("postpage.html", blog=blog, current_user=self.user)


class Register(Handler):

    def get(self):

        self.render("signup.html")

    def post(self):

        self.name = self.request.get("name")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASS_RE = re.compile(r"^.{3,20}$")
        MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

        name_valid = USER_RE.match(self.name)
        password_valid = PASS_RE.match(self.password)
        email_valid = MAIL_RE.match(self.email)

        is_error = False

        params = dict(name=self.name, email=self.email)

        if not name_valid:
            is_error = True
            params['username_error'] = "Not a valid name!"

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
        # make sure user doesn't already exist
        u = User.by_name(self.name)
        if u:
            self.render("signup.html",
                        username_error="User with that name already exists")
        else:
            u = User.register(name=self.name,
                              password=self.password,
                              email=self.email)
            u.put()
            self.login(u)
            self.redirect("/welcome")


class Login(Handler):

    def get(self):

        self.render("login.html")

    def post(self):

        name = self.request.get("name")
        password = self.request.get("password")

        u = User.login(name, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            self.render('login.html', error="Invalid login")


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/')


class WelcomePage(Handler):

    def get(self):
        # refers to initialize function in Handler
        if self.user:
            self.render("welcome.html", name=self.user.name)
        else:
            self.redirect('/signup')


class EditPost(Handler):

    def get(self, author, blog_id):
        """
        When you use " (\d+) ", app sends this number as a parameter
        (of type string) to the get or post methods
        """
        u = User.by_name(author)
        user_id = u.key.id()
        blog = Blog.by_id(int(blog_id), int(user_id))
        if not blog:
            self.error(404)
            return
        owner = False
        if self.is_owner(blog):
            self.render("edit.html", blog=blog)
        else:
            self.error(401)
            return

    def post(self, author, blog_id):

        subject = self.request.get("subject")
        content = self.request.get("content")
        u = User.by_name(author)
        user_id = u.key.id()
        blog = Blog.by_id(int(blog_id), int(user_id))

        if subject and content:

            blog.subject = subject
            blog.content = content
            blog.put()

            self.redirect("/%s/%d" % (author, int(blog_id)))
        else:

            if self.is_owner(blog):
                blog.key.delete()
                self.redirect("/")
            else:
                self.error(401)
                return


class LikeHandler(Handler):

    def get(self):
        self.error(404)
        return


    def post(self):
        # logging.debug(self.request.body)
        data = json.loads(self.request.body)
        blog_key = ndb.Key(urlsafe=data['blog_key'])
        user_key_ndb = get_user_key(self.user.key.id())
        like = Like.get_user_like(user_key=self.user.key, blog_key=blog_key)
        if not like:
            like = Like(parent=user_key_ndb, blog=blog_key)
            like.put()
            likes = blog_key.get().get_likes()
            self.response.out.write(json.dumps(({'likes': likes+1})))
        else:
            like.key.delete()
            likes = blog_key.get().get_likes()
            if (likes-1) == 0:
                likes = ''
                self.response.out.write(json.dumps(({'likes': likes})))
            self.response.out.write(json.dumps(({'likes': likes-1})))

        logging.debug(likes)


class CommentHandler(Handler):

    def get(self):
        self.error(404)
        return


    def post(self):
        # think about escaping input

        data = json.loads(self.request.body)
        # logging.debug(data['blog_key'])
        # logging.debug(data['content'])
        logging.debug("1")


        if 'blog_key' in data:
            #new comment
            logging.debug("newcomment")
            blog_key = ndb.Key(urlsafe=data['blog_key'])
            content = data['content']
            user_key_ndb = get_user_key(self.user.key.id())
            if content:
                c = Comment(parent=user_key_ndb, blog=blog_key, content=content)
                comment = c.put()

                comment_html = comment.get().render(self.user)
                """
                we render new comments without current_user to avoid
                updating/deleting dynamic objects

                """
                logging.debug(comment_html)

                # newcomment = {'author': self.user.name, 'content': content}
                self.response.out.write(json.dumps(({'comment': comment_html})))
        else:
            if 'content' in data:
                logging.debug("3")
                #edit comment
                comment_key = ndb.Key(urlsafe=data['comment_key'])
                c = comment_key.get()
                c.content = data['content']
                c.put()
                self.response.out.write(json.dumps(({'comment_key': data['comment_key'], 'content': c.content})))  
            else:
                logging.debug("2")
                #delete comment
                comment_key = ndb.Key(urlsafe=data['comment_key'])
                comment_key.delete()
                self.response.out.write(json.dumps(({'comment_key': data['comment_key']})))  


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', NewPost),
                               ('/([a-zA-Z0-9_-]{3,20})/(\d+)', PostPage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', WelcomePage),
                               ('/edit/([a-zA-Z0-9_-]{3,20})/(\d+)', EditPost),
                               ('/like', LikeHandler),
                               ('/comment', CommentHandler),
                               ],
                              debug=True)
