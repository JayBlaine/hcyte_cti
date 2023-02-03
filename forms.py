from flask_wtf import FlaskForm, RecaptchaField
from wtforms import (StringField, BooleanField, RadioField, EmailField, SelectMultipleField, widgets)
from wtforms.validators import InputRequired, Length
import wtforms


class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class EmailForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(),
                                             Length(min=2, max=100)])
    last_name = StringField('Last Name', validators=[InputRequired(),
                                                  Length(min=2, max=100)])
    org = StringField('Organization/University', validators=[InputRequired(),
                                                     Length(min=2, max=100)])
    email = EmailField('Email', validators=[InputRequired()])
    interest = MultiCheckboxField('Interest',
                       choices=['More Information', 'Data Sharing', 'Collaboration'])
    recaptcha = RecaptchaField()
