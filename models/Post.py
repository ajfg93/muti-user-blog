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