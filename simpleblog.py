import webapp2
import re
import json
import random
from string import letters
import models
import core

from google.appengine.ext import ndb


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        # t = jinja_env.get_template(template)
        # return t.render(params)
        return core.render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = core.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and core.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and models.User.by_id(int(uid))


class MainPage(Handler):

    def render_main(self):
        blogs = models.Blog.query().order(-models.Blog.created)
        self.render(
            "blog.html", blogs=blogs, current_user=self.user)

    def get(self):
        self.render_main()


class NewPost(Handler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect("/login")
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            user_key = models.get_user_key(self.user.key.id())
            b = models.Blog(subject=subject, content=content, parent=user_key)
            b.put()
            """
            We create new URL for post
            from author's name and blog's numeric id
            """
            author = self.user.name
            blog_id = b.key.id()
            self.redirect("/%s/%d" % (author, blog_id))
        else:
            error = "We need both a subject and some text!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)


class PostPage(Handler):

    def get(self, author, blog_id):
        """
        When you use REGEX in url, app sends strings as a parameter
        to the get or post methods
        """
        u = models.User.by_name(author)
        user_id = u.key.id()
        blog = models.Blog.by_id(int(blog_id), int(user_id))
        if not blog:
            self.error(404)
            return
        self.render("postpage.html", blog=blog, current_user=self.user)


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
        # making sure user doesn't already exist
        u = models.User.by_name(self.name)
        if u:
            self.render("signup.html",
                        username_error="models.User with that name already exists")
        else:
            u = models.User.register(name=self.name,
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
        # authenticate
        u = models.User.login(name, password)
        if u:
            # update cookies
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
        u = models.User.by_name(author)
        user_id = u.key.id()
        blog = models.Blog.by_id(int(blog_id), int(user_id))
        if not blog:
            self.error(404)
            return
        owner = False
        if blog.is_owner(self.user):
            self.render("edit.html", blog=blog)
        else:
            self.error(401)
            return

    def post(self, author, blog_id):
        subject = self.request.get("subject")
        content = self.request.get("content")
        u = models.User.by_name(author)
        user_id = u.key.id()
        blog = models.Blog.by_id(int(blog_id), int(user_id))
        if not blog.is_owner(self.user):
            self.error(401)
            return
        if subject and content:
            blog.subject = subject
            blog.content = content
            blog.put()
            self.redirect("/%s/%d" % (author, int(blog_id)))
        else:
            # this is additional backend check for ownership
            # before deleting content
            if blog.is_owner(self.user):
                blog.key.delete()
                self.redirect("/")
            else:
                self.error(401)
                return


class LikeHandler(Handler):

    def get(self):
        # To make sure URL is not available directly
        self.error(404)
        return

    def post(self):
        # we use AJAX for post request
        data = json.loads(self.request.body)
        """
        We use ndb.urlsafe() method to transfer
        key of the post we want to like through JSON object
        """
        blog_key = ndb.Key(urlsafe=data['blog_key'])
        blog = blog_key.get()
        if blog.is_owner(self.user):
            self.error(401)
            return
        # Check if user has already liked the blog
        like = models.Like.get_user_like(user_key=self.user.key, blog_key=blog_key)
        if not like:
            # Create parent key for new like
            user_key_ndb = models.get_user_key(self.user.key.id())
            like = models.Like(parent=user_key_ndb, blog=blog_key)
            like.put()
            likes = blog_key.get().get_likes()
            self.response.out.write(
                json.dumps(({'likes': likes+1, 'blog_key': data['blog_key']})))
        else:
            # liking post twice revokes like
            like.key.delete()
            likes = blog_key.get().get_likes()
            """
            We want to pass likes count back
            We would post temporary count as text
            So we want to be sure it is not 0
            """
            if (likes-1) == 0:
                likes = ''
                self.response.out.write(
                    json.dumps(({'likes': likes,
                                 'blog_key': data['blog_key']})))
            else:
                self.response.out.write(
                    json.dumps(({'likes': likes-1,
                                 'blog_key': data['blog_key']})))


class CommentHandler(Handler):

    def get(self):
        self.error(404)
        return

    def post(self):
        """
        This method is used for all operations with comments:
        create new, delete or edit
        """
        if not self.user:
            self.redirect("/login")
        data = json.loads(self.request.body)
        if 'blog_key' in data:
            # Means user posting new comment
            blog_key = ndb.Key(urlsafe=data['blog_key'])
            content = data['content']
            user_key_ndb = models.get_user_key(self.user.key.id())
            if content:
                c = models.Comment(
                    parent=user_key_ndb, blog=blog_key, content=content)
                comment = c.put()
                # We create same comment html for temporary object to display
                comment_html = comment.get().render(self.user)
                self.response.out.write(
                    json.dumps(({'comment': comment_html})))
        else:
            if 'content' in data:
                # update comment
                comment_key = ndb.Key(urlsafe=data['comment_key'])
                c = comment_key.get()
                if c:
                    if not c.is_owner(self.user):
                        self.error(401)
                        return
                    c.content = data['content']
                    c.put()
                    self.response.out.write(
                        json.dumps(({'comment_key': data['comment_key'],
                                 'content': c.content})))
            else:
                # delete comment
                comment_key = ndb.Key(urlsafe=data['comment_key'])
                c = comment_key.get()
                if not c.is_owner(self.user):
                        self.error(401)
                        return
                comment_key.delete()
                self.response.out.write(
                    json.dumps(({'comment_key': data['comment_key']})))


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
