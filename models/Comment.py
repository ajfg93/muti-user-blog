class Comment(db.Model):
    content = db.TextProperty(required = True)
    user = db.ReferenceProperty(User)
    post_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_id(cls, comment_id):
        return Comment.get_by_id(comment_id)
