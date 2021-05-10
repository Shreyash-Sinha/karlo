from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, SelectField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


class Task(FlaskForm):
    name = StringField('Title', validators=[DataRequired()])
    description = StringField('Description', [DataRequired()])
    priority = SelectField('Priority Level', validators=[DataRequired()], choices=['High', 'Medium', 'Low'])
    submit = SubmitField('ADD')


class NewUser(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("SIGN ME UP!")


class LoginUser(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("LET ME IN!")
