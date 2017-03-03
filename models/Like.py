class Like(db.Model):
    post_id = db.IntegerProperty(required = True)
    isLike = db.BooleanProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)