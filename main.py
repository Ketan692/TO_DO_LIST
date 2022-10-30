import sqlalchemy.exc
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime

date = datetime.date.today().strftime("%d-%m-%Y")
year = datetime.date.today().strftime("%Y")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("TO_DO_LIST")

#Connect to Database
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///tasks.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    tasks = db.relationship('Task', backref='user')


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(250), nullable=False)
    status = db.Column(db.String(250), nullable=False)
    date_of_est = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


try:
    Task.query.filter_by(user_id=None).delete()
    db.session.commit()
except sqlalchemy.exc.OperationalError:
    pass
except AttributeError:
    pass



@app.route("/", methods=["GET", "POST"])
def home():
    tasks = []
    if current_user.is_authenticated:
        all_tasks = db.session.query(Task).all()
        for t in all_tasks:
            if t.user_id == current_user.id:
                tasks.append(t)
        return render_template('index.html', t=tasks[::-1], user_name=current_user.name, date=date, year=year)
    else:
        heading = f"MY TASKLIST {date}"
        all_tasks = db.session.query(Task).all()
        for t in all_tasks:
            if t.user_id == None:
                tasks.append(t)
        return render_template('index.html', task_title=heading, t=tasks[::-1], len_of_tasks=len(tasks),  year=year)


@app.route("/k", methods=["GET", "POST"])
def submitted():
    if request.method == "POST":
        if current_user.is_authenticated:
            task = request.form.get('task')
            new_task = Task(
                task=task,
                status="PENDING",
                user_id=current_user.id,
                date_of_est=date
            )

            db.session.add(new_task)
            db.session.commit()
        else:
            task = request.form.get('task')
            new_task = Task(
                task=task,
                status="PENDING",
                date_of_est=date
            )

            db.session.add(new_task)
            db.session.commit()
    return redirect(url_for('home'))


@app.route("/delete_all_tasks")
def refresh():
    if current_user.is_authenticated:
        Task.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
    else:
        Task.query.filter_by(user_id=None).delete()
        db.session.commit()
    return redirect(url_for('home'))


@app.route("/delete/<cc>")
def delete_task(cc):
    tasks = db.session.query(Task).all()
    for t in tasks:
        if t.task == str(cc):
            db.session.delete(t)
            db.session.commit()
            print(t.task, cc)
            break

    return redirect(url_for('home'))


@app.route("/update/<cc>", methods=["GET", "POST"])
def status(cc):
    tasks = db.session.query(Task).all()
    for t in tasks:
        if t.id == int(cc):
            if t.status == "COMPLETED":
                t.status = "PENDING"
            else:
                t.status = "COMPLETED"
            db.session.commit()
            print(t.task, cc)
            break
    return redirect(url_for('home'))


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(username=email).first()

        if not user:
            flash("Enter the correct email address.")
            print(222)
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            print(111)
            flash("please enter correct password")
            return redirect(url_for('login'))
        else:
            login_user(user)
            print(333)
            return redirect(url_for('home'))
    print(456)
    return render_template("login.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    email = request.form.get("email")
    password = request.form.get("password")
    name = request.form.get("name")
    if request.method == "POST":

        # If user's email already exists
        if User.query.filter_by(username=email).first():
            # Send flash messsage
            flash("You've already signed up with that email, log in instead!")
            # Redirect to /login route.
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            username=email,
            name=name,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        # login_user(new_user)
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
