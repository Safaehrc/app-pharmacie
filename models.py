from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

# Modèle Utilisateur
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)  # Nouveau champ pour l'e-mail
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")  # Default role is "user"

# Modèle Médicament
class Medicament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    quantity = db.Column(db.Integer, nullable=False)
    dosage = db.Column(db.String(50), nullable=False)
    expiration = db.Column(db.Date, nullable=False)
    price = db.Column(db.Float, nullable=False)  # Prix unitaire
    form = db.Column(db.String(50), nullable=False)  # Forme pharmaceutique
    category = db.Column(db.String(100), nullable=False)  # Catégorie thérapeutique

    

# Modèle Commande
class Commande(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    medicament_id = db.Column(db.Integer, db.ForeignKey('medicament.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    date_commande = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="Pending")

    user = db.relationship('User', backref='commandes')
    medicament = db.relationship('Medicament', backref='commandes')
    delivery_details = db.relationship('DeliveryDetails', back_populates='commande', cascade="all, delete-orphan", uselist=False)
    
    @property
    def total(self):
        if self.medicament and self.quantity:
            return round(self.medicament.price * self.quantity, 2)
        return 0
# Modéle DeliveryDetails
class DeliveryDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    commande_id = db.Column(db.Integer, db.ForeignKey('commande.id'), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(255), nullable=False)

    commande = db.relationship('Commande', back_populates='delivery_details')


# Modéle SupportMessage
class SupportMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, default=datetime.utcnow)