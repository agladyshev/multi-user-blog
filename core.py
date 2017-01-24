import hmac
import jinja2
import os
from passlib.hash import pbkdf2_sha256


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


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
    return pbkdf2_sha256.hash(password)


def valid_pw(password, hashed):
    return pbkdf2_sha256.verify(password, hashed)