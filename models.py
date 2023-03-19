from database import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    salt = db.Column(db.String, nullable=False)

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
    checked = db.Column(db.Boolean, default=False)
    shopping_list_id = db.Column(db.Integer, db.ForeignKey('shopping_list.id'), nullable=False)
    shopping_list = db.relationship('ShoppingList', backref=db.backref('items', lazy=True))
    grocery_type_id = db.Column(db.Integer, db.ForeignKey('grocery_type.id'), nullable=True)
    grocery_type = db.relationship('GroceryType', backref=db.backref('items', lazy=True))

def add_grocery_types():
    grocery_types = ['Meat', 'Dairy', 'Fruits', 'Vegetables', 'Bakery', 'Frozen', 'Canned Goods', 'Beverages', 'Other']
    for grocery_type in grocery_types:
        if not GroceryType.query.filter_by(name=grocery_type).first():
            db.session.add(GroceryType(name=grocery_type))
    db.session.commit()