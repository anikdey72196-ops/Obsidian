from extensions import db
import datetime


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(255))

    user = db.relationship('User', backref=db.backref('expenses', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'category': self.category,
            'date': self.date.strftime('%Y-%m-%d'),
            'description': self.description
        }


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime, default=_utc_now, nullable=False, index=True)

    def __repr__(self):
        return f"<LoginAttempt ip={self.ip_address} at={self.attempted_at}>"
