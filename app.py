from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime,timedelta, timezone
from functools import wraps
from models import db, bcrypt, User, Medicament, Commande, DeliveryDetails, SupportMessage
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from smtplib import SMTPAuthenticationError, SMTPException
import csv
from flask import Response
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'votre_cle_secrete'

db.init_app(app)
bcrypt.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuration de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Vérifiez que le serveur est correct
app.config['MAIL_PORT'] = 587  # Assurez-vous que le port est correct
app.config['MAIL_USE_TLS'] = True  # TLS doit être activé
app.config['MAIL_USERNAME'] = 'pharmaciesansaf@gmail.com'  # Remplacez par votre e-mail
app.config['MAIL_PASSWORD'] = 'txuy fnzg wxmx pqao'  # Remplacez par votre mot de passe ou mot de passe d'application
app.config['MAIL_DEFAULT_SENDER'] = 'pharmaciesansaf@gmail.com'  # L'expéditeur doit être valide

mail = Mail(app)

# Générateur de token sécurisé
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])



def generate_reset_token(user_email):
    return serializer.dumps(user_email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != "admin":
            flash("Accès refusé : Vous n'avez pas les droits nécessaires.", "danger")
            return redirect(url_for("stock"))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/statistiques')
@login_required
@admin_required
def statistiques():
    total_medicaments = Medicament.query.count()
    total_commandes = Commande.query.count()
    total_utilisateurs = User.query.count()
    commandes_en_attente = Commande.query.filter_by(status="Pending").count()
    medicaments_faible_stock = Medicament.query.filter(Medicament.quantity < 10).all()
    medicaments_expiration_proche = Medicament.query.filter(
        Medicament.expiration <= datetime.utcnow().date() + timedelta(days=30)
    ).all()
      # Calcul du nombre de jours avant expiration pour chaque médicament
    today = datetime.utcnow().date()
    for med in medicaments_expiration_proche:
        med.days_until_expiration = (med.expiration - today).days
        
    return render_template(
        'statistiques.html',
        total_medicaments=total_medicaments,
        total_commandes=total_commandes,
        total_utilisateurs=total_utilisateurs,
        commandes_en_attente=commandes_en_attente,
        medicaments_faible_stock=medicaments_faible_stock,
        medicaments_expiration_proche=medicaments_expiration_proche
    )

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    return render_template("base.html")  # Affiche la page d'accueil

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")  # Récupérer l'e-mail
        password = request.form.get("password")
        user = User.query.filter_by(username=username, email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Connexion réussie", "success")
            return redirect(url_for("stock"))
        else:
            flash("Adresse e-mail ou Nom d'utilisateur ou mot de passe incorrect", "danger")

    return render_template("login.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Vérification du format de l'e-mail
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            flash("Adresse e-mail invalide.", "danger")
            return render_template("register.html")

        # Vérification de la complexité du mot de passe
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[0-9]', password):
            flash("Le mot de passe doit contenir au moins 8 caractères, une majuscule et un chiffre.", "danger")
            return render_template("register.html")

        # Vérification des doublons
        if User.query.filter_by(username=username).first():
            flash("Ce nom d'utilisateur est déjà pris.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Cet e-mail est déjà utilisé.", "danger")
            return render_template("register.html")
        
         # Attribution automatique du rôle
        if email.lower() == "pharmaciesansaf@gmail.com":
            role = "admin"
        else:
            role = "user"

        # Création de l'utilisateur
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash("Compte créé avec succès !", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route('/stock', methods=['GET'])
@login_required
def stock():
    query = request.args.get("q", "")
    sort_by = request.args.get("sort_by", "name")  # Default sorting by name
    sort_order = request.args.get("sort_order", "asc")  # Default ascending order
    page = request.args.get("page", 1, type=int)
    per_page = 10

    sort_column = getattr(Medicament, sort_by, Medicament.name)
    if sort_order == "desc":
        sort_column = sort_column.desc()

    if query:
        articles = Medicament.query.filter(Medicament.name.ilike(f"%{query}%")).order_by(sort_column).paginate(page=page, per_page=per_page)
    else:
        articles = Medicament.query.order_by(sort_column).paginate(page=page, per_page=per_page)

    if not articles.items:
        flash("Aucun médicament trouvé.", "info")
    return render_template("stock.html", articles=articles, sort_by=sort_by, sort_order=sort_order)

@app.route('/ajout', methods=['GET', 'POST'])
@login_required
@admin_required
def ajout():
    if request.method == 'POST':
        name = request.form.get("articleName")
        quantity = request.form.get("articleQuantity")
        dosage = request.form.get("articleDosage")
        expiration = request.form.get("articleExpiration")
        price = request.form.get("articlePrice")
        form = request.form.get("articleForm")
        category = request.form.get("articleCategory")

        # Vérification des champs obligatoires
        if not name or not quantity or not dosage or not expiration or not price or not form or not category:
            flash("Tous les champs sont obligatoires.", "danger")
            return render_template("ajout.html")

        # Vérification des valeurs numériques
        try:
            quantity = int(quantity)
            price = float(price)
            if quantity <= 0 or price <= 0:
                raise ValueError
        except ValueError:
            flash("La quantité et le prix doivent être des valeurs numériques positives.", "danger")
            return render_template("ajout.html")

        # Vérification de la date d'expiration
        try:
            expiration_date = datetime.strptime(expiration, "%Y-%m-%d").date()
            if expiration_date <= datetime.utcnow().date():
                flash("La date d'expiration doit être dans le futur.", "danger")
                return render_template("ajout.html")
        except ValueError:
            flash("Format de date invalide. Utilisez le format AAAA-MM-JJ.", "danger")
            return render_template("ajout.html")

        # Ajout du médicament
        new_medicament = Medicament(
            name=name,
            quantity=quantity,
            dosage=dosage,
            expiration=expiration_date,
            price=price,
            form=form,
            category=category
        )
        db.session.add(new_medicament)
        db.session.commit()
        flash("Médicament ajouté avec succès !", "success")
        return redirect(url_for("stock"))

    return render_template("ajout.html")


@app.route('/delete_article', methods=['POST'])
@login_required
@admin_required  # Restreindre l'accès aux administrateurs
def delete_article():
    article_id = request.form.get("articleId")
    article = Medicament.query.get(article_id)
    if article:
        db.session.delete(article)
        db.session.commit()
        flash("Médicament supprimé", "success")
    else:
        flash("Erreur : Médicament introuvable.", "danger")
    return redirect(url_for("stock"))


@app.route('/edit_article/<int:article_id>', methods=['GET', 'POST'])
@login_required
@admin_required  # Restreindre l'accès aux administrateurs
def edit_article(article_id):
    article = Medicament.query.get_or_404(article_id)

    if request.method == 'POST':
        try:
            # Récupération des données du formulaire
            article.name = request.form.get("newName").strip()
            article.quantity = int(request.form.get("newQuantity"))
            article.dosage = request.form.get("newDosage").strip()
            expiration = request.form.get("newExpiration")
            article.expiration = datetime.strptime(expiration, '%Y-%m-%d').date()
            article.price = float(request.form.get("newPrice"))
            article.form = request.form.get("newForm").strip()
            article.category = request.form.get("newCategory").strip()

            # Validations supplémentaires
            if article.quantity <= 0:
                flash("Erreur : La quantité doit être un nombre entier positif.", "danger")
                return redirect(url_for("edit_article", article_id=article_id))

            if article.expiration < datetime.now().date():
                flash("Erreur : La date d'expiration doit être dans le futur.", "danger")
                return redirect(url_for("edit_article", article_id=article_id))

            # Enregistrement des modifications
            db.session.commit()
            flash("Médicament modifié avec succès", "success")
            return redirect(url_for("stock"))

        except ValueError:
            flash("Erreur dans la modification des données. Vérifiez les champs.", "danger")
            return redirect(url_for("edit_article", article_id=article_id))

    return render_template("edit_article.html", article=article)

from sqlalchemy.orm import joinedload

@app.route('/mes_commandes')
@login_required
def mes_commandes():
    commandes = Commande.query.filter_by(user_id=current_user.id).options(joinedload(Commande.delivery_details)).all()
    for commande in commandes:
        print(commande.delivery_details)
    return render_template("mes_commandes.html", commandes=commandes)
   
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Déconnexion réussie", "info")
    return redirect(url_for("home"))  # Redirige vers la page d'accueil après déconnexion

@app.template_filter('is_near_expiration')
def is_near_expiration(expiration_date):
    return expiration_date <= datetime.now(timezone.utc).date() + timedelta(days=30)


@app.route('/all_commandes', methods=['GET'])
@login_required
@admin_required
def all_commandes():
    sort_by = request.args.get("sort_by", "date_commande")
    sort_order = request.args.get("sort_order", "desc")
    page = request.args.get('page', 1, type=int)

    if sort_by == "user":
        sort_column = User.username
        query = Commande.query.join(User, Commande.user_id == User.id)
    else:
        sort_column = getattr(Commande, sort_by, Commande.date_commande)
        query = Commande.query

    if sort_order == "desc":
        sort_column = sort_column.desc()

    # Récupérer les commandes avec pagination (par exemple, 10 commandes par page)
    commandes_pagination = query.order_by(sort_column).paginate(page=page, per_page=10)

    # Passez l'objet Pagination complet au template
    return render_template(
        "all_commandes.html",
        commandes=commandes_pagination,
        sort_by=sort_by,
        sort_order=sort_order
    )

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message(
                "Réinitialisation de mot de passe",
                recipients=[email],
                body=f"Pour réinitialiser votre mot de passe, cliquez sur le lien suivant : {reset_url}"
            )
            try:
                mail.send(msg)
                flash("Un e-mail de réinitialisation a été envoyé.", "info")
            except Exception as e:
                flash(f"Erreur lors de l'envoi de l'e-mail : {e}", "danger")
        else:
            flash("Aucun utilisateur trouvé avec cet e-mail.", "warning")
        return redirect(url_for('confirmation_page'))
    return render_template("forgot_password.html")

@app.route('/confirmation_page')
def confirmation_page():
    return render_template('confirmation_page.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash("Le lien de réinitialisation est invalide ou a expiré.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for('reset_password', token=token))

        # Mettre à jour le mot de passe de l'utilisateur
        user = User.query.filter_by(email=email).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash("Votre mot de passe a été réinitialisé avec succès.", "success")
            return redirect(url_for('login'))
        else:
            flash("Utilisateur introuvable.", "danger")
            return redirect(url_for('forgot_password'))

    return render_template("reset_password.html", token=token)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/update_commande/<int:commande_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def update_commande(commande_id):
    commande = Commande.query.get_or_404(commande_id)
    if request.method == 'POST':
        new_status = request.form.get("status")
        if new_status in ["Pending", "Expédiée", "Livrée", "Approuvée", "Refusée"]:
            commande.status = new_status
            db.session.commit()
            flash("Statut de la commande mis à jour avec succès.", "success")
        else:
            flash("Statut invalide.", "danger")
        return redirect(url_for("all_commandes"))
    return render_template("update_commande.html", commande=commande)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")

        # Vérifiez si le nom d'utilisateur est déjà pris par un autre utilisateur
        if username != current_user.username and User.query.filter_by(username=username).first():
            flash("Ce nom d'utilisateur est déjà pris.", "danger")
            return redirect(url_for("profile"))

        current_user.username = username
        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            current_user.password = hashed_password

        db.session.commit()
        flash("Profil mis à jour avec succès.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=current_user)

@app.route('/contact_support')
@login_required
def contact_support():
    return render_template('contact_support.html')



@app.route('/submit_contact_form', methods=['POST'])
def submit_contact_form():
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')

    # Enregistrer le message dans la base de données
    new_message = SupportMessage(name=name, email=email, message=message)
    db.session.add(new_message)
    db.session.commit()

    flash("Votre message a été envoyé avec succès.", "success")
    return redirect(url_for('contact_support'))

@app.route('/admin/messages', methods=['GET'])
@login_required
@admin_required
def view_messages():
    messages = SupportMessage.query.order_by(SupportMessage.date_sent.desc()).all()
    return render_template('admin_messages.html', messages=messages)

@app.route('/test_email')
def test_email():
    try:
        msg = Message(
            "Test Email",
            recipients=["pharmaciesansaf@gmail.com"],  # Remplacez par une adresse valide
            body="Ceci est un e-mail de test envoyé depuis Flask."
        )
        mail.send(msg)
        return "E-mail envoyé avec succès !"
    except Exception as e:
        return f"Erreur lors de l'envoi de l'e-mail : {e}"


@app.route('/download_stock', methods=['GET'])
@login_required
def download_stock():
    # Supprimer la restriction pour les administrateurs
    if current_user.role not in ["user", "admin"]:
        flash("Accès refusé : Vous n'avez pas les droits nécessaires pour télécharger la fiche du stock.", "danger")
        return redirect(url_for("stock"))

    # Récupérer les médicaments du stock
    medicaments = Medicament.query.all()

    # Créer un fichier CSV en mémoire
    def generate_csv():
        import io
        output = io.StringIO()
        writer = csv.writer(output, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        # Écrire l'en-tête
        writer.writerow(["Nom", "Quantité", "Dosage", "Expiration", "Prix", "Forme", "Catégorie"])

        # Écrire les données
        for medicament in medicaments:
            writer.writerow([
                medicament.name,
                medicament.quantity,
                medicament.dosage,
                medicament.expiration.strftime('%d/%m/%Y'),
                f"{medicament.price:.2f} MAD",
                medicament.form,
                medicament.category
            ])

        # Ajouter un BOM pour l'encodage UTF-8
        return '\ufeff' + output.getvalue()

    # Retourner le fichier CSV en tant que réponse
    return Response(
        generate_csv(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=stock_medicaments.csv"}
    )

@app.route('/annuler_commande/<int:commande_id>', methods=['POST'])
@login_required
def annuler_commande(commande_id):
    commande = Commande.query.get_or_404(commande_id)

    # Vérifier si la commande appartient à l'utilisateur connecté
    if commande.user_id != current_user.id:
        flash("Vous n'êtes pas autorisé à annuler cette commande.", "danger")
        return redirect(url_for("mes_commandes"))

    # Vérifier si la commande est encore annulable
    if commande.status not in ["Pending"]:
        flash("La commande ne peut pas être annulée car elle a déjà été validée ou expédiée.", "warning")
        return redirect(url_for("mes_commandes"))

    # Restaurer le stock du médicament
    medicament = Medicament.query.get(commande.medicament_id)
    if medicament:
        medicament.quantity += commande.quantity

    # Supprimer la commande (les détails associés seront supprimés automatiquement)
    db.session.delete(commande)
    db.session.commit()

    flash("Commande annulée avec succès.", "success")
    return redirect(url_for("mes_commandes"))

@app.route('/commander/<int:medicament_id>', methods=['GET', 'POST'])
@login_required
def commander(medicament_id):
    medicament = Medicament.query.get_or_404(medicament_id)

    # Valeurs par défaut
    phone = "06********"
    address = "Rue de la Paix"
    quantity = "1"

    if request.method == 'POST':
        form_submitted = True
        phone = request.form.get('phone', "")
        address = request.form.get('address', "")
        quantity = request.form.get('quantity', "")

        # Validation des champs
        if not phone or not address:
            flash("Veuillez fournir un numéro de téléphone et une adresse.", "danger")
            return render_template(
                "commander.html",
                medicament=medicament,
                form_submitted=form_submitted,
                phone=phone,
                address=address,
                quantity=quantity
            )

        if not quantity or int(quantity) <= 0 or int(quantity) > medicament.quantity:
            flash("Quantité invalide ou stock insuffisant.", "danger")
            return render_template(
                "commander.html",
                medicament=medicament,
                form_submitted=form_submitted,
                phone=phone,
                address=address,
                quantity=quantity
            )

        # Création de la commande
        medicament.quantity -= int(quantity)
        commande = Commande(
            user_id=current_user.id,
            medicament_id=medicament.id,
            quantity=int(quantity)
        )
        db.session.add(commande)
        db.session.flush()

        delivery_details = DeliveryDetails(
            commande_id=commande.id,
            phone=phone,
            address=address
        )
        db.session.add(delivery_details)
        db.session.commit()

        flash("Commande passée avec succès !", "success")
        return redirect(url_for("stock"))

    # Pour GET, form_submitted doit être False
    return render_template(
        "commander.html",
        medicament=medicament,
        form_submitted=False,
        phone=phone,
        address=address,
        quantity=quantity
    )



import json
# Charger les données du chatbot au démarrage de l'application
with open('data_chatbot/data.json', 'r', encoding='utf-8') as file:
    medication_data = json.load(file)

@app.route('/chatbot', methods=['GET', 'POST'])
@login_required
def chatbot():
    if request.method == 'GET':
        return render_template('chatbot.html')

    elif request.method == 'POST':
        data = request.json
        question = data.get("question", "").lower()

        # Trouver le nom du médicament dans la question
        medication_name = None
        for name in medication_data.keys():
            if name.lower() in question:
                medication_name = name
                break

        if not medication_name:
            return {"answer": "Désolé, je n'ai pas trouvé d'informations sur ce médicament."}, 404

        # Récupérer les informations du médicament
        medication = medication_data.get(medication_name)

        # Générer une réponse selon les mots-clés en français
        if "effets" in question or "secondaires" in question:
            answer = medication.get("effets_secondaires", "Aucune information sur les effets secondaires.")
        elif "utilisation" in question or "comment" in question or "prendre" in question:
            answer = medication.get("utilisation", "Aucune information sur l'utilisation.")
        elif "précaution" in question or "attention" in question:
            answer = medication.get("precautions", "Aucune information sur les précautions.")
        elif "contre-indications" in question:
            answer = medication.get("contre_indications", "Aucune information sur les contre-indications.")
        elif "interactions" in question or "interaction" in question:
            answer = medication.get("interactions", "Aucune information sur les interactions médicamenteuses.")
        elif "temps d'action" in question or "durée d'effet" in question:
            answer = medication.get("temps_action_duree", "Aucune information sur le temps d'action ou la durée d'effet.")
        elif "conseils" in question or "particuliers" in question:
            answer = medication.get("conseils_particuliers", "Aucune information sur les conseils particuliers.")
        else:
            answer = "Je suis désolé, je n'ai pas compris votre question."

        return {"answer": answer}, 200
    



from datetime import datetime, timedelta

@app.template_filter('expiration_status')
def expiration_status_filter(expiration_date):
    today = datetime.today().date()
    delta = (expiration_date - today).days
    
    if delta < 0:
        return 'expired'
    elif delta < 30:
        return 'warning'
    else:
        return 'valid'    



from flask_login import login_required, current_user, logout_user

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    if user.role == "admin":
        flash("Vous ne pouvez pas supprimer le compte administrateur.", "danger")
        return redirect(url_for('profile'))
    # Supprimer toutes les commandes et autres données liées si besoin
    Commande.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash("Votre compte a été supprimé.", "success")
    return redirect(url_for('home'))

from flask import send_file, flash, redirect, url_for
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors  # Ajoutez ceci
import io

@app.route('/facture/<int:commande_id>')
@login_required
def telecharger_facture(commande_id):
    commande = Commande.query.get_or_404(commande_id)
    if current_user.role != "admin" and commande.user_id != current_user.id:
        flash("Vous n'avez pas accès à cette facture.", "danger")
        return redirect(url_for('mes_commandes'))

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)

    # Titre en bleu
    p.setFont("Helvetica-Bold", 16)
    p.setFillColor(colors.HexColor("#2a5a78"))
    p.drawString(50, 800, f"Facture - Commande #{commande.id}")

    # Texte normal en noir
    p.setFont("Helvetica", 12)
    p.setFillColor(colors.black)
    p.drawString(50, 780, f"Date : {commande.date_commande.strftime('%d/%m/%Y %H:%M')}")
    p.drawString(50, 760, f"Client : {commande.user.username} ({commande.user.email})")
    p.drawString(50, 740, f"Téléphone : {commande.delivery_details.phone}")
    p.drawString(50, 720, f"Adresse : {commande.delivery_details.address}")

    # En-tête du tableau en gris
    p.setFillColor(colors.HexColor("#4a4a4a"))
    p.drawString(50, 690, "Médicament")
    p.drawString(200, 690, "Dosage")
    p.drawString(300, 690, "Quantité")
    p.drawString(370, 690, "Prix unitaire")
    p.drawString(470, 690, "Total")

    # Ligne en gris clair
    p.setStrokeColor(colors.HexColor("#cccccc"))
    p.line(50, 685, 550, 685)

    # Détail de la commande en noir
    p.setFillColor(colors.black)
    p.drawString(50, 670, commande.medicament.name)
    p.drawString(200, 670, commande.medicament.dosage)
    p.drawString(300, 670, str(commande.quantity))
    p.drawString(370, 670, f"{commande.medicament.price} MAD")
    p.drawString(470, 670, f"{commande.total} MAD")

    # Total en bleu foncé
    p.setFont("Helvetica-Bold", 12)
    p.setFillColor(colors.HexColor("#2a5a78"))
    p.drawString(50, 630, f"Prix total à payer : {commande.total} MAD")

    # Footer en gris
    p.setFont("Helvetica", 10)
    p.setFillColor(colors.HexColor("#888888"))
    p.drawString(50, 600, "Merci pour votre confiance. Pharmacie Sansaf.")

    p.showPage()
    p.save()
    buffer.seek(0)
    filename = f"facture_commande_{commande.id}.pdf"
    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True)