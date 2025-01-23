from flask import Flask, render_template, redirect, url_for, request, session, g, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length
from flask_bcrypt import Bcrypt  # For password hashing
import json
from datetime import datetime
import re
import pickle
import numpy as np

app = Flask(__name__)
app.secret_key = 'heart_disease_prediction_secret_key_123'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Initialize Bcrypt

# Form class
class RegistrationForm(FlaskForm):
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=10, max=10)])
    Pro = SelectField('Profession', choices=[
        ('Student', 'Student'),
        ('Engineer', 'Engineer'),
        ('Doctor', 'Doctor'),
        ('Other', 'Other')
    ])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

# Models
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(120), unique=False, nullable=False)
    Password = db.Column(db.String(120), unique=False, nullable=False)

class Doclogs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Firstname = db.Column(db.String(120), unique=False, nullable=False)
    Lastname = db.Column(db.String(120), unique=False, nullable=False)
    Ph = db.Column(db.Integer, unique=False, nullable=False)
    Profession = db.Column(db.String(120), unique=False, nullable=False)
    Email = db.Column(db.String(20), unique=False, nullable=False)
    Username = db.Column(db.String(120), unique=False, nullable=False)
    Password = db.Column(db.String(120), unique=False, nullable=False)

class Hdpuser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    FirstName = db.Column(db.String(120), unique=False, nullable=False)
    LastName = db.Column(db.String(120), unique=False, nullable=False)
    Email = db.Column(db.String(20), unique=False, nullable=False)
    Ph_no = db.Column(db.Integer, unique=False, nullable=False)
    Profession = db.Column(db.String(12), unique=False, nullable=False)
    Username = db.Column(db.String(120), unique=False, nullable=False)
    Password = db.Column(db.String(120), unique=False, nullable=False)

class Emails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Email = db.Column(db.String(120), unique=False, nullable=False)

class Dataset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Age = db.Column(db.Integer, unique=False, nullable=False)
    Sex = db.Column(db.Integer, unique=False, nullable=False)
    Cp = db.Column(db.Integer, unique=False, nullable=False)
    Trestbps = db.Column(db.Integer, unique=False, nullable=False)
    Chol = db.Column(db.Integer, unique=False, nullable=False)
    Fbs = db.Column(db.Integer, unique=False, nullable=False)
    Restecg = db.Column(db.Integer, unique=False, nullable=False)
    Thalach = db.Column(db.Integer, unique=False, nullable=False)
    Exang = db.Column(db.Integer, unique=False, nullable=False)
    Oldpeak = db.Column(db.Integer, unique=False, nullable=False)
    Slope = db.Column(db.Integer, unique=False, nullable=False)
    Ca = db.Column(db.Integer, unique=False, nullable=False)
    Thal = db.Column(db.Integer, unique=False, nullable=False)
    Target = db.Column(db.Integer, unique=False, nullable=False)

# Load logged-in user into g.user
@app.before_request
def load_logged_in_user():
    g.user = None
    if 'user' in session:
        g.user = session['user']

# Create all tables and add admin if not exists
with app.app_context():
    db.create_all()
    existing_admin = Admin.query.filter_by(Username="admin").first()
    if not existing_admin:
        hashed_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
        admin = Admin(Username="admin", Password=hashed_password)
        db.session.add(admin)
        db.session.commit()

# Routes
@app.route('/doctorlogin', methods=['GET', 'POST'])
def doclogin():
    msg = ""
    if request.method == 'POST':
        uname = request.form['username']
        passd = request.form['password']
        user1 = Doclogs.query.filter_by(Username=uname).first()
        if user1 and bcrypt.check_password_hash(user1.Password, passd):
            session['user'] = uname
            return render_template('docindex.html', user1=user1)
        else:
            msg = "Wrong Credentials!"
    return render_template('doclogin.html', msg=msg)

@app.route('/dash')
def dash():
    d = Dataset.query.all()
    co = Hdpuser.query.all()
    co1 = Doclogs.query.all()
    co2 = Dataset.query.all()
    count = len(co)
    count1 = len(co1)
    count2 = len(co2)
    c22 = count2 // 2
    return render_template('dash.html', d=d, count=count, count1=count1, count2=count2, c22=c22)

@app.route('/patientlogin', methods=['GET', 'POST'])
def patlog():
    msg = ""
    if request.method == 'POST':
        uname = request.form['username']
        passd = request.form['password']
        user1 = Hdpuser.query.filter_by(Username=uname).first()
        if user1 and bcrypt.check_password_hash(user1.Password, passd):
            session['user'] = uname
            return render_template('profilepatient.html', user1=user1)
        else:
            msg = "Wrong Credentials!"
    return render_template('patlogin.html', msg=msg)

@app.route('/docregis', methods=['GET', 'POST'])
def docregis():
    form = RegistrationForm()
    if request.method == 'POST' and form.validate():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        entry = Doclogs(
            Firstname=form.firstname.data,
            Lastname=form.lastname.data,
            Email=form.email.data,
            Ph=form.phone.data,
            Profession=form.Pro.data,
            Username=form.username.data,
            Password=hashed_password
        )
        db.session.add(entry)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('doclogin'))
    return render_template('docregis.html', form=form)

@app.route('/pattable', methods=['GET', 'POST'])
def adminview():
    c = Hdpuser.query.all()
    return render_template('pattable.html', c=c)

@app.route('/doctable', methods=['GET', 'POST'])
def adminvdoc():
    c = Doclogs.query.all()
    return render_template('doctable.html', c=c)

@app.route('/emailcount', methods=['GET'])
def emailcount():
    c = Emails.query.all()
    return render_template('emailscount.html', c=c)

@app.route('/heartcheck', methods=['GET', 'POST'])
def heartcheck():
    return render_template("heartcheck.html")

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        model = pickle.load(open(r'D:\keval\study\Projects\hdp\Heart_Disease_Prediction-FLask-\modal2.pkl', 'rb'))
        int_features = [int(x) for x in request.form.values()]
        final_features = [np.array(int_features)]
        prediction = model.predict(final_features)
        output = round(prediction[0], 2)
        if output == 1:
            o = "Bad News! There is a chance that you have a heart disease."
            return render_template('heartcheck.html', prediction_text='Heart status: {}'.format(o))
        else:
            o = "Good News! There is no chance that you have a heart disease! :)"
            return render_template('heartcheck.html', prediction_text2='Heart status: {}'.format(o))
    return redirect('/predict')

@app.route('/docpredict', methods=['POST'])
def docpredict():
    if request.method == 'POST':
        model = pickle.load(open(r'D:\keval\study\Projects\hdp\Heart_Disease_Prediction-FLask-\modal2.pkl', 'rb'))
        int_features = [int(x) for x in request.form.values()]
        final_features = [np.array(int_features)]
        prediction = model.predict(final_features)
        output = round(prediction[0], 2)
        if output == 1:
            o = "Bad News! There is a chance that you have a heart disease."
            return render_template('heartcheck.html', prediction_text='Heart status: {}'.format(o))
        else:
            o = "Good News! There is no chance that you have a heart disease! :)"
            return render_template('heartcheck.html', prediction_text2='Heart status: {}'.format(o))
    return redirect('/docpredict')

@app.route('/viewdatatable')
def viewdatatable():
    ds = Dataset.query.all()
    c = Doclogs.query.filter_by(Username=g.user).first()
    return render_template('datatable.html', ds=ds, c=c)

@app.route('/docindex')
def docindex():
    curr = Doclogs.query.filter_by(Username=g.user).first()
    return render_template('docindex.html', curr=curr)

@app.route('/viewpatient')
def viewpatient():
    patient = Hdpuser.query.all()
    c = Doclogs.query.filter_by(Username=g.user).first()
    return render_template('viewpatient.html', patient=patient, c=c)

@app.route('/userprofile')
def userprofile():
    c = Doclogs.query.filter_by(Username=g.user).first()
    return render_template('userprofile.html', c=c)

@app.route('/docupdate', methods=['GET', 'POST'])
def docupdate():
    if request.method == 'POST':
        d = Doclogs.query.filter_by(Username=g.user).first()
        d.Firstname = request.form['name1']
        d.Lastname = request.form['name2']
        d.Email = request.form['email']
        d.Ph = request.form['phone']
        d.Profession = request.form['pro']
        db.session.commit()
        flash("Doctor Details Updated Successfully")
        return redirect("userprofile")

@app.route('/profilepat')
def profilepat():
    c = Hdpuser.query.filter_by(Username=g.user).first()
    return render_template('profilepatient.html', c=c)

@app.route('/checkheart', methods=['GET', 'POST'])
def checkheart():
    return render_template('checkheart.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST' and form.validate():
        email_check = Hdpuser.query.filter_by(Email=form.email.data).first()
        phone_check = Hdpuser.query.filter_by(Ph_no=form.phone.data).first()
        username_check = Hdpuser.query.filter_by(Username=form.username.data).first()

        if email_check:
            flash('Email address already exists')
        elif phone_check:
            flash('Phone number already exists')
        elif username_check:
            flash('Username already taken')
        elif not re.match(r'[789]\d{9}$', form.phone.data):
            flash('Invalid phone number!')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            entry = Hdpuser(
                FirstName=form.firstname.data,
                LastName=form.lastname.data,
                Email=form.email.data,
                Ph_no=form.phone.data,
                Profession=form.Pro.data,
                Username=form.username.data,
                Password=hashed_password
            )
            db.session.add(entry)
            db.session.commit()
            flash('Registration successful!')
            return redirect(url_for('patlog'))
    return render_template('register.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)
    
    
