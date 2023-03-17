# main.py
from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, JWTManager
from dotenv import load_dotenv
import os

from flask_jwt_extended.exceptions import NoAuthorizationError
from sqlalchemy.orm import sessionmaker
from database import db
import hashlib, binascii
from functools import wraps
from flask_jwt_extended.view_decorators import jwt_required as original_jwt_required, verify_jwt_in_request
from functools import wraps, partial

load_dotenv()
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'shopping_list.db')
app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
jwt = JWTManager(app)
db.init_app(app)


from models import User, ShoppingList, Item, GroceryType, add_grocery_types



def jwt_required(fn=None, optional=False):
    if fn is None:
        return partial(jwt_required, optional=optional)
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            access_token = request.cookies.get("access_token")
            if access_token:
                request.environ["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
            verify_jwt_in_request()
            return fn(*args, **kwargs)
        except NoAuthorizationError:
                return redirect(url_for('login'))

    return wrapper


@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == 'GET':
        return render_template('register.html')


    if request.method == 'POST':
        print("register you found me: ")
        username = request.form['username']
        print(username)
        encrypted_password = request.form['password']
        print(encrypted_password)
        salt = request.form['salt']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'success': False, 'error': 'Username already exists'})

        user = User(username=username, password=encrypted_password, salt=salt)
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User registered successfully'})

@app.route('/api/user/<username>', methods=['GET'])
def get_user_salt(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'salt': user.salt})
    return jsonify({'error': 'User not found'}), 404

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form['username']

        print(username)
        encrypted_password = request.form['password']

        print(encrypted_password)
        user = User.query.filter_by(username=username).first()

        print(user.password)

        if user and encrypted_password == user.password:
            print("true")
            access_token = create_access_token(identity=user.id)
            response = make_response(jsonify({"message": "Login successful"}))
            response.set_cookie("access_token", access_token, httponly=True, secure=True)
            return response
        else:
            return jsonify({"error": "Invalid credentials"}), 401

@app.route('/shopping_lists', methods=['GET', 'POST'])
@jwt_required(optional=True)
def shopping_lists():
    print("hello")
    user_id = get_jwt_identity()
    if user_id is not None:
        user = User.query.get(user_id)
        if request.method == 'POST':
            name = request.form['name']
            shopping_list = ShoppingList(name=name, user=user)
            db.session.add(shopping_list)
            db.session.commit()
        encrypted_shopping_lists = user.shopping_lists
        return render_template('shopping_lists.html', shopping_lists=encrypted_shopping_lists)
    return redirect(url_for('login'))


@app.route('/shopping_list/<int:shopping_list_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required(optional=True)
def shopping_list(shopping_list_id):
    user_id = get_jwt_identity()
    shopping_list = ShoppingList.query.filter_by(id=shopping_list_id, user_id=user_id).first()
    if not shopping_list:
        return jsonify({'error': 'Shopping list not found'})

    if request.method == 'GET':
        encrypted_items = [{'id': item.id, 'encrypted_name': item.name, 'encrypted_quantity': item.quantity, 'encrypted_price': item.price} for item in
                 shopping_list.items]
        return jsonify({'id': shopping_list.id, 'encrypted_name': shopping_list.name, 'encrypted_items': encrypted_items})

    if request.method == 'PUT':
        encrypted_name = request.form['encrypted_name']  # Use 'encrypted_name' instead of 'name'
        shopping_list.name = encrypted_name
        db.session.commit()
        return jsonify({'message': 'Shopping list updated'})

    if request.method == 'DELETE':
        db.session.delete(shopping_list)
        db.session.commit()
        return jsonify({'message': 'Shopping list deleted'})

@app.route('/grocery_types', methods=['GET'])
@jwt_required(optional=True)
def grocery_types():
    types = GroceryType.query.all()
    return jsonify([{'id': t.id, 'name': t.name} for t in types])

@app.route('/item', methods=['POST'])
@jwt_required(optional=True)
def add_item():
    encrypted_name = request.form['encrypted_name']
    shopping_list_id = request.form['shopping_list_id']
    encrypted_quantity = int(request.form.get('encrypted_quantity', 1))
    encrypted_price = request.form.get('encrypted_price', None)
    grocery_type_id = request.form.get('grocery_type_id', None)

    item = Item(name=encrypted_name, shopping_list_id=shopping_list_id, quantity=encrypted_quantity,
                price=encrypted_price, grocery_type_id=grocery_type_id)
    db.session.add(item)
    db.session.commit()
    return jsonify({'message': 'Item added'})

@app.route('/item/<int:item_id>', methods=['PUT', 'DELETE'])
@jwt_required(optional=True)
def item(item_id):

    user_id = get_jwt_identity()
    item = Item.query.get(item_id)
    if not item or item.shopping_list.user_id != user_id:
        return jsonify({'error': 'Item not found'})

    if request.method == 'PUT':
        encrypted_name = request.form.get('encrypted_name', item.name)
        encrypted_quantity = request.form.get('encrypted_quantity', item.quantity)
        encrypted_price = request.form.get('encrypted_price', item.price)

        item.name = encrypted_name
        item.quantity = encrypted_quantity
        item.price = float(encrypted_price) if encrypted_price else None

        db.session.commit()
        return jsonify({'message': 'Item updated'})

    if request.method == 'DELETE':
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item deleted'})

@app.route('/login.html', methods=['GET'])
def login_page():
    return render_template('login.html')


@app.route('/register.html', methods=['GET'])
def register_page():
    return render_template('register.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_grocery_types()

        engine = db.get_engine()
        Session = sessionmaker(bind=engine)
    app.run(debug=True)

