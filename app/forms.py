from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField, SelectField, validators, SelectMultipleField, widgets
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from .models import UserRole
from flask_wtf.file import FileField, FileAllowed

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class UploadFileForm(FlaskForm):
    file = FileField('Upload PDF', validators=[DataRequired()])
    submit = SubmitField('Upload')

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired

class AddBookForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    author = StringField('Author', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    book_file = FileField('Book File (PDF)', validators=[
        DataRequired(),
        FileAllowed(['pdf'], 'PDF files only!')
    ])
    cover_image = FileField('Cover Image', validators=[
        FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')
    ])
    genres = SelectMultipleField('Select Genres', 
                              coerce=int,
                              choices=[])  # Removed validators
    new_genre = StringField('Add New Genre (comma-separated for multiple)')
    is_featured = BooleanField('Feature this book')
    submit = SubmitField('Add Book')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')

class UserRoleForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Role', 
                     choices=[(role.value, role.name.replace('_', ' ').title()) 
                             for role in UserRole],
                     validators=[DataRequired()])
    submit = SubmitField('Save')

