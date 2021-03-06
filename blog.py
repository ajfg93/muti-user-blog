import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2
import logging
from google.appengine.ext import db
from functools import wraps


# Jinja environment initialize
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

##### user related functions
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

## Regular expression match functions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

####Models
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user = db.ReferenceProperty(User)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self, cuid = None):
        self._render_text = self.content.replace('\n', '<br>')
        comments = Comment.all().filter('post_id = ', self.key().id())
        l_cnt = Like.all().filter('post_id = ', self.key().id()).filter( 'isLike = ', True).count()
        ul_cnt = Like.all().filter('post_id = ', self.key().id()).filter( 'isLike = ', False).count()
        cuid_like_record = Like.all().filter('post_id = ', self.key().id()).filter( 'user_id = ', cuid).get()
        return render_str("post.html", p = self, cuid = cuid, comments = comments, l_cnt = l_cnt, ul_cnt = ul_cnt, cuid_like_record = cuid_like_record)

class Comment(db.Model):
    content = db.TextProperty(required = True)
    user = db.ReferenceProperty(User)
    post_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_id(cls, comment_id):
        return Comment.get_by_id(comment_id)

class Like(db.Model):
    post_id = db.IntegerProperty(required = True)
    isLike = db.BooleanProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

## Decorators
def post_exists(function):
    @wraps(function)
    def wrapper(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            return function(self, post_id, post)
        else:
            self.error(404)
            return
    return wrapper

def user_owns_post(function):
    @wraps(function)
    def wrapper(self, post_id, post = None):
        if (post.user.key().id() == self.user.key().id()):
            return function(self, post_id, post)
        else:
            error_msg = "you can't edit or delete others' post."
            self.render('redirect.html', error_msg = error_msg)
    return wrapper

def user_not_owns_post(function):
    @wraps(function)
    def wrapper(self, post_id, post = None):
        if (post.user.key().id() != self.user.key().id()):
            return function(self, post_id, post)
        else:
            error_msg = "you can't like or dislike your own post"
            self.render('redirect.html', error_msg = error_msg)
    return wrapper

def comment_exists(function):
    @wraps(function)
    def wrapper(self, comment_id):
        comment = Comment.by_id(int(comment_id))
        if comment:
            return function(self, comment_id, comment)
        else:
            self.error(404)
            return
    return wrapper

def user_owns_comment(function):
    @wraps(function)
    def wrapper(self, comment_id, comment = None):
        if (self.user.key().id() == comment.user.key().id()):
            return function(self, comment_id, comment)
        else:
            error_msg = "you can't edit or delete this comment"
            self.render('redirect.html', error_msg = error_msg)
    return wrapper

def scrollBar_position(function):
    @wraps(function)
    def wrapper(self, post_id):
        s_postion = self.request.get('scrollPosition')
        self.set_unsecure_cookie(s_postion)
        return function(self, post_id)
    return wrapper

def user_logged_in(function):
    @wraps(function)
    def wrapper(self, post_id = None):
        if self.user:
            return function(self, post_id)
        else:
            return self.redirect('/login')
    return wrapper

## Handlers
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    #set scroll position cookie   
    def set_unsecure_cookie(self, val):
        name = 's_position'
        cookie_str = str('%s=%s; Path=/' % (name, val))
        self.response.headers.add_header('Set-Cookie', cookie_str)

    #read scroll position cookie   
    def read_unsecure_cookie(self):
        name = 's_position'
        cookie_val = self.request.cookies.get(name)
        return cookie_val

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class MainPage(BlogHandler):
  def get(self):
      self.render("test.html", test = 123)

class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        scrollPosition = self.read_unsecure_cookie()
        if scrollPosition:
            scrollPosition = int(scrollPosition)
        else:
            scrollPosition = 0
        self.render('front.html', posts = posts, scrollPosition = scrollPosition)

class PostPage(BlogHandler):
    @post_exists
    def get(self, post_id, post):
        self.render("permalink.html", post = post, scrollPosition = 0)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/blog')

# Implentmented class 
# like == 1 == like, like == 0 == unlike
class LikePost(BlogHandler):
    @scrollBar_position
    @user_logged_in
    @post_exists
    @user_not_owns_post
    def post(self, post_id, post):
        like = Like.all().filter('post_id = ', int(post_id)).filter('user_id = ', self.user.key().id()).get()
        like_dislike = self.request.get('like')
        if like:
            #if the user has liked before, update the data with latest value
            like.isLike = bool(int(like_dislike))
            like.put()
            return self.redirect('/blog')
        else:
            #if the user never likes or dislike, insert a new data with submitted value
            like = Like(post_id = int(post_id), isLike = bool(like_dislike), user_id = self.user.key().id())
            like.put()
            return self.redirect('/blog')

class DeleteLike(BlogHandler):
    @scrollBar_position
    @user_logged_in
    def post(self, post_id):
        like = Like.all().filter('post_id = ', int(post_id)).filter('user_id = ', self.user.key().id()).get()
        if like:
            like.delete()
            return self.redirect('/blog')
        else:
            error_msg = "you have no data to delete"
            self.render('redirect.html', error_msg = error_msg)

class NewComment(BlogHandler):
    @scrollBar_position
    @user_logged_in
    @post_exists
    def post(self, post_id, post):
        content = self.request.get('content')
        new_comment = Comment(content = content, user = self.user, post_id = post.key().id())
        new_comment.put()
        return self.redirect("/blog")

class EditComment(BlogHandler):
    @scrollBar_position
    @user_logged_in
    @comment_exists
    @user_owns_comment
    def post(self, comment_id, comment):
        content = self.request.get('content')
        comment.content = content
        comment.put()
        return self.redirect('/blog')


class DeleteComment(BlogHandler):
    @scrollBar_position
    @user_logged_in
    @comment_exists
    @user_owns_comment
    def post(self, comment_id, comment):
        comment.delete()
        return self.redirect('/blog')
          

class NewPost(BlogHandler):
    @user_logged_in
    def get(self, post_id = None):
        self.render("newpost.html")

    @user_logged_in
    def post(self, post_id = None):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, user = self.user)
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(BlogHandler):
    @user_logged_in
    @post_exists
    @user_owns_post
    def get(self, post_id, post):
        subject = post.subject
        content = post.content
        self.render("editpost.html", subject=subject, content=content)

    @user_logged_in
    @post_exists
    @user_owns_post
    def post(self, post_id, post):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            return self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject, content=content, error=error)
 
class DeletePost(BlogHandler):
    @scrollBar_position
    @user_logged_in
    @post_exists
    @user_owns_post
    def post(self, post_id, post):
        #delete all related comments
        comments = Comment.all().filter('post_id = ', post_id )
        for c in comments:
            c.delete()
        #delete all related like records
        likes = Like.all().filter('post_id = ', post_id)
        for l in likes:
            l.delete()
        #delete the post
        post.delete()
        return self.redirect('/blog')
     

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/newpost', NewPost),
                               ('/blog/comment/([0-9]+)', NewComment),
                               ('/blog/comment/edit/([0-9]+)', EditComment),
                               ('/blog/comment/delete/([0-9]+)', DeleteComment),
                               ('/blog/like/([0-9]+)', LikePost),
                               ('/blog/delete_like/([0-9]+)', DeleteLike),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
