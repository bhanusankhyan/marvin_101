from flask import Flask, render_template, flash, request, redirect, flash
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from flask import session as login_session
import requests
from flask_security import Security, login_required,  SQLAlchemySessionUserDatastore, login_user, logout_user
from database_setup import db_session, init_db, Base
from models import User, Role
from flask_security.forms import LoginForm, Required
from wtforms import IntegerField


class ExtendedLoginForm(LoginForm):
    phone = IntegerField('Phone Number')


app = Flask(__name__)
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = '$2a$16$PnnIgfMwkOjGX4SkHqSOPO'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/bhanu/Documents/final_build/flask9/marvin.db?check_same_thread=False'


user_datastore = SQLAlchemySessionUserDatastore(db_session,User, Role)
security = Security(app, user_datastore, login_form = ExtendedLoginForm)


@app.context_processor
def Dashboard_details():
    navbar_items = {'Home':'/','Components':[{'name':'title1','link':'#'},{'name':'title2','link':'#'}], 'Dropdown':[{'name':'title1', 'link':'#'},{'name':'title2','link':'#'}]}
    user_menu_items = [{'name':'Profile','link':'#','class':'fe fe-user'},{'name':'Settings','link':'#','class':'fe-settings'},
    {'name':'Inbox','link':'#','class':'fe fe-mail'},{'name':'Message','link':'#','class':'fe-send'},
    {'name':'Need Help?','link':'#','class':'fe-help-circle'},{'name':'SignOut','link':"/logout",'class':'fe-log-out'}]
    sidebar_items = [{'name':'title1','link':'#','class':'fe-alert-triangle'},{'name':'title2','link':'#','class':'fe-user'},{'name':'title3','link':'#','class':'fe-image'}]
    return dict(navbar_items = navbar_items,user_menu_items = user_menu_items, sidebar_items = sidebar_items , type = type, str = str)



@app.route('/')
@login_required
def home():
    return render_template('index.html')


@app.route('/otp', methods=['POST','GET'])
def OTP():
    if request.method == 'GET':
             return render_template('otp.html')
    if request.method == 'POST':
        otp = request.form['otp']
        resp = requests.get('https://api-v3.redcarpetup.com/app_number_verify', {'mobile':login_session['phone'],'code':otp})
        if resp.text != 'Code':
            user = db_session.query(User).filter_by(phone = login_session['phone']).first()
            login_user(user)
            return redirect('/')
        elif resp.text == 'Code':
            return render_template('otp.html')



@app.route('/login_user',methods=['POST'])
def LoginUser():
    if request.method == 'POST':
        phone = request.form['phone']
        password = request.form['password']
        user = db_session.query(User).filter_by(phone = int(phone)).first()
        try:
            if(user != None):
                if user.password == password and user.phone == int(phone):
                    login_session['phone'] = int(phone)
                    r = requests.get('https://api-v3.redcarpetup.com/app_number', {'mobile':phone,'name': password,'email': 'aa@gmail.com'})
                    return redirect('/otp')
                else:
                    flash("Incorrect Credentials")
                    return redirect('/login')


            else:
                flash("Please Register")
                return redirect('/login')
        except:
            flash("Please Register")
            return redirect('/login')


@app.route('/register',methods = ['POST', 'GET'])
def Register():
    if request.method == 'GET':
        return render_template('security/register_user.html')


@app.route('/logout')
def Logout():
    del login_session['phone']
    logout_user()
    return redirect('/')

@app.route('/reset_password', )
def ForgotPassword():
        return render_template('forgot_password.html')





if __name__ == '__main__':
    app.secret_key = 'new_secret_key'
    app.run(host = '0.0.0.0',port= 8000, debug = True)
