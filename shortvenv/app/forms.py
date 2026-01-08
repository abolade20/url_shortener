from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, URL, Optional

class RegistrationForm(FlaskForm):
    """Form for user registration"""
    email = StringField('Email', validators=[DataRequired(message='Email is required'),Email(message='Invalid email address')])
    username = StringField('Username', validators=[DataRequired(message='Username is required'),Length(min=3, max=20, message='Username must be between 3 and 20 characters')])
    password = PasswordField('Password', validators=[DataRequired(message='Password is required'),Length(min=6, message='Password must be at least 6 characters long')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(message='Please confirm your password'),EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign Up')
    # CSRF is automatically enabled by FlaskForm


class LoginForm(FlaskForm):
    """Form for user login (PRD 2.1: User Authentication)"""
    email = StringField('Email', validators=[DataRequired(message='Email is required'),Email(message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(message='Password is required')])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class NewURLForm(FlaskForm):
    """Form for creating shortened URLs (PRD 2.3: URL Shortening)"""
    original_url = StringField('Long URL', validators=[DataRequired(message='URL is required'),URL(message='Invalid URL. Please enter a valid URL (e.g., https://example.com)')])
    custom_alias = StringField('Custom Short Code (Optional)', validators=[Optional(),Length(min=3, max=20, message='Custom code must be between 3 and 20 characters')])
    submit = SubmitField('Shorten URL')


class SearchForm(FlaskForm):
    """Form for searching/filtering URLs on dashboard (PRD 2.2: Dashboard)"""
    query = StringField('Search', validators=[Optional(),Length(max=100, message='Search query too long')])
    submit = SubmitField('Search')