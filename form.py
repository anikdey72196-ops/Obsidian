from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp

USERNAME_PATTERN = r'^[a-zA-Z0-9_.-]+$'
USERNAME_MSG = "Username can only contain letters, numbers, dots, hyphens, and underscores."

class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[
        DataRequired(),
        Length(min=3, max=80, message="Username must be between 3 and 80 characters."),
        Regexp(USERNAME_PATTERN, message=USERNAME_MSG)
    ])
    password = PasswordField('password', validators=[
        DataRequired(),
        Length(min=8, max=72, message="Password must be between 8 and 72 characters.")
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('username', validators=[
        DataRequired(),
        Length(max=80),
        Regexp(USERNAME_PATTERN, message=USERNAME_MSG)
    ])
    password = PasswordField('password', validators=[DataRequired(), Length(max=72)])
    submit = SubmitField('Sign In')
