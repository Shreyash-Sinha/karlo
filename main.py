from flask import *
from flask_bootstrap import Bootstrap
from functools import wraps
from flask_ckeditor import CKEditor
from datetime import date
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
import os
from forms import *

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///karlo.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    tasks = relationship("Tasks", back_populates="parent_post")


class Tasks(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    body = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("User", back_populates="tasks")


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        email = form.name.data
        password = form.password.data

        user = User.query.filter_by(name=email).first()
        if not user:
            flash("That profile does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('dashboard', index=user.id))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = NewUser()
    if form.validate_on_submit():

        if User.query.filter_by(name=form.name.data).first():
            print(User.query.filter_by(name=form.name.data).first())
            flash("Username already in use")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        user = User.query.filter_by(name=form.name.data).first()
        return redirect(url_for("dashboard", index=user.id))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/dashboard/<int:index>')
def dashboard(index):
    user = User.query.get(index)
    if not user == None:
        if current_user.is_authenticated:
            if current_user.id == index:
                return render_template('dashboard.html', user=user, current_user=current_user)
            else:
                return redirect(url_for('home'))
        else:
            return redirect(url_for('home'))
    else:
        return redirect(url_for('home'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/add_task', methods=['POST', 'GET'])
def add_task():
    if current_user.is_authenticated:
        form = Task()
        if form.validate_on_submit():
            title = form.name.data
            body = form.description.data
            priority = form.priority.data
            user = User.query.get(current_user.id)
            new = Tasks(
                name=title,
                body=body,
                priority=priority,
                parent_post=user
            )
            db.session.add(new)
            db.session.commit()
            return redirect(url_for('dashboard', index=current_user.id))
        return render_template('add_task.html', form=form)
    else:
        return redirect(url_for('login'))


@app.route('/delete/<int:index_dash>/<int:index_task>', methods=['POST', 'GET'])
def delete(index_dash, index_task):
    if current_user.is_authenticated:
        if current_user.id == index_dash:
            try:
                task = Tasks.query.get(index_task)
                db.session.delete(task)
                db.session.commit()
                return redirect(url_for('dashboard', index=index_dash))
            except:
                return redirect(url_for('dashboard', index=index_dash))
        else:
            return redirect(url_for('dashboard', index=index_dash))
    else:
        return redirect(url_for('dashboard', index=index_dash))


if __name__ == '__main__':
    app.run(debug=True)