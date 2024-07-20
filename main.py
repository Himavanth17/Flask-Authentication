import werkzeug.security
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)



# CREATE TABLE IN DB
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
 
 
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User,user_id)

@app.route('/')
def home():
    return render_template("index.html",logged_in=current_user.is_authenticated)


@app.route('/register',methods = ['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        get_password = request.form.get('password')
        password = werkzeug.security.generate_password_hash(get_password, method='pbkdf2',salt_length=16)
        new_user = User(
            name = name,
            email = email,
            password = password
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('secrets'))
    return render_template("register.html",logged_in = current_user.is_authenticated)


@app.route('/login',methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if not user:
            flash("email does not exist")
            return redirect(url_for('login'))

        if not werkzeug.security.check_password_hash(user.password,password):
            flash("password is incorrect")
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html", logged_in = current_user.is_authenticated)


@app.route('/secrets')
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    directory = r"C:\Users\Himavanth Reddy\PycharmProjects\Flask\Flask Authentication Day 68\static\files"
    filename = "cheat_sheet.pdf"
    return send_from_directory(directory,filename)


if __name__ == "__main__":
    app.run(debug=True)
