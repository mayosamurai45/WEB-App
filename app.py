from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from uuid import uuid4
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config['SECURITY_PASSWORD_SALT'] = 'your_salt_here'


db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)


roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    items = db.relationship('Item', backref='category', lazy=True)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=True)
    fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.fs_uniquifier:
            self.fs_uniquifier = str(uuid4())


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


with app.app_context():
    db.create_all()

    if not User.query.filter_by(email='admin@example.com').first():
        hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
        user_datastore.create_user(email='admin@example.com', password=hashed_password)
        db.session.commit()


password = "password"
hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
print(hashed_password)


@app.route('/')
def index():
    categories = Category.query.all()
    items = Item.query.all()
    return render_template('index.html', categories=categories, items=items)


@app.route('/categories', methods=['POST'])
@login_required
def create_category():
    data = request.form
    new_category = Category(name=data['name'])
    db.session.add(new_category)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/categories/<int:id>', methods=['DELETE'])
@login_required
def delete_category(id):
    category = Category.query.get_or_404(id)
    db.session.delete(category)
    db.session.commit()
    return jsonify({'message': 'Category deleted'})


@app.route('/items', methods=['POST'])
@login_required
def create_item():
    data = request.form
    new_item = Item(name=data['name'], description=data['description'], category_id=data['category_id'])
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/items/<int:id>/edit', methods=['POST'])
@login_required
def update_item(id):
    data = request.form
    item = Item.query.get_or_404(id)
    item.name = data['name']
    item.description = data['description']
    item.category_id = data['category_id']
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/items/<int:id>/delete', methods=['POST'])
@login_required
def delete_item(id):
    item = Item.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/login', methods=['POST'])
@csrf.exempt
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=user.id)
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401


if __name__ == '__main__':
    app.run(debug=True)
