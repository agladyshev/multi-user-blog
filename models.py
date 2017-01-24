from google.appengine.ext import ndb

import core


def users_key(group='default'):
    # default root entity
    return ndb.Key('users', group)


def get_user_key(user_id):
    """
    All user entities are child ent. of default root entity
    Blogs, comments and likes are child entities of user entities
    """
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
        pw_hash = core.make_pw_hash(password)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, password):
        u = cls.by_name(name)
        if u and core.valid_pw(password, u.pw_hash):
            return u


class Blog(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

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
        # current_user is none if user is not authenticated
        self._render_text = self.content.replace('\n', '<br>')
        comments = self.get_comments()
        likes = self.get_likes()
        return core.render_str("entry.html",
                          blog=self,
                          comments=comments,
                          likes=likes,
                          current_user=current_user)

    @classmethod
    def by_id(cls, blog_id, user_id):
        """
        We can't retrieve blog by id only because id is not unique.
        Ids are used as a part of url, alongside with the author name

        """
        parent = get_user_key(user_id)
        return cls.get_by_id(blog_id, parent=parent)


class Comment(ndb.Model):
    blog = ndb.KeyProperty(kind=Blog, required=True)
    content = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

    def is_owner(self, current_user=None):
        if current_user:
            return self.key.parent() == current_user.key

    def render(self, current_user=None):
        self._render_text = self.content.replace('\n', '<br>')
        return core.render_str("comment.html",
                          comment=self,
                          current_user=current_user)

    @classmethod
    def by_blog_key(cls, blog_key):
        comments = cls.query().filter(
            Comment.blog == blog_key).order(Comment.created)
        return comments


class Like(ndb.Model):
    blog = ndb.KeyProperty(kind=Blog, required=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_blog_key(cls, blog_key):
        likes = cls.query().filter(Like.blog == blog_key)
        return likes

    @classmethod
    def get_user_like(cls, user_key, blog_key):
        # Checks if user has liked blog already, return object or null
        return cls.query(ancestor=user_key).filter(Like.blog == blog_key).get()