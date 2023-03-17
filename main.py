# main.py

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask import session, redirect, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shopping_list.db'
app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600

jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

class ShoppingList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('shopping_lists', lazy=True))

class GroceryType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    quantity = db.Column(db.String, nullable=False, default=1)
    price = db.Column(db.String, nullable=True)
    shopping_list_id = db.Column(db.Integer, db.ForeignKey('shopping_list.id'), nullable=False)
    shopping_list = db.relationship('ShoppingList', backref=db.backref('items', lazy=True))
    grocery_type_id = db.Column(db.Integer, db.ForeignKey('grocery_type.id'), nullable=True)
    grocery_type = db.relationship('GroceryType', backref=db.backref('items', lazy=True))

db.create_all()

def add_grocery_types():
    grocery_types = ['Meat', 'Dairy', 'Fruits', 'Vegetables', 'Bakery', 'Frozen', 'Canned Goods', 'Beverages']
    for grocery_type in grocery_types:
        if not GroceryType.query.filter_by(name=grocery_type).first():
            db.session.add(GroceryType(name=grocery_type))
    db.session.commit()

add_grocery_types()



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    encrypted_password = request.form['encrypted_password']
    user = User(username=username, password=encrypted_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    encrypted_password = request.form['encrypted_password']
    user = User.query.filter_by(username=username, password=encrypted_password).first()
    if user:
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token})
    return jsonify({'error': 'Invalid credentials'})


@app.route('/shopping_lists', methods=['GET', 'POST'])
@jwt_required
def shopping_lists():
    user_id = get_jwt_identity()

    if request.method == 'POST':
        encrypted_name = request.form['encrypted_name']
        shopping_list = ShoppingList(name=encrypted_name, user_id=user_id)
        db.session.add(shopping_list)
        db.session.commit()
        return jsonify({'message': 'Shopping list created'})

    shopping_lists = ShoppingList.query.filter_by(user_id=user_id).all()
    return jsonify([{'id': sl.id, 'encrypted_name': sl.name} for sl in shopping_lists])


@app.route('/shopping_list/<int:shopping_list_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required
def shopping_list(shopping_list_id):
    user_id = get_jwt_identity()
    shopping_list = ShoppingList.query.filter_by(id=shopping_list_id, user_id=user_id).first()
    if not shopping_list:
        return jsonify({'error': 'Shopping list not found'})

    if request.method == 'GET':
        items = [{'id': item.id, 'encrypted_name': item.name, 'encrypted_quantity': item.quantity, 'encrypted_price': item.price} for item in
                 shopping_list.items]
        return jsonify({'id': shopping_list.id, 'encrypted_name': shopping_list.name, 'encrypted_items': items})

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
@jwt_required
def grocery_types():
    types = GroceryType.query.all()
    return jsonify([{'id': t.id, 'name': t.name} for t in types])

@app.route('/item', methods=['POST'])
@jwt_required
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
@jwt_required
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



if __name__ == '__main__':
    app.run(debug=True)