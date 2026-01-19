from flask import Flask, render_template, request, redirect, url_for, abort, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reciclaje.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'clave_secreta_para_login'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    correo = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    rol = db.Column(db.String(20), default='usuario')  # 'usuario' o 'admin'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Encuesta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    respuesta1 = db.Column(db.String(200))
    respuesta2 = db.Column(db.String(200))
    respuesta3 = db.Column(db.String(200))
    respuesta4 = db.Column(db.String(200))
    respuesta5 = db.Column(db.String(200))
    fecha = db.Column(db.DateTime, default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

def solo_admin(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        if not current_user.is_authenticated or current_user.rol != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorador

with app.app_context():
    db.create_all()
    if not Usuario.query.filter_by(correo="admin@gmail.com").first():
        admin = Usuario(correo="admin@gmail.com", rol="admin")
        admin.set_password("1234")
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def inicio():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    mensaje = ""
    if request.method == 'POST':
        correo = request.form.get('correo')
        password = request.form.get('password')
        usuario = Usuario.query.filter_by(correo=correo).first()
        if usuario and usuario.check_password(password):
            login_user(usuario)
            return redirect(url_for('index'))
        mensaje = "Correo o contraseña incorrectos"
    return render_template('login.html', mensaje=mensaje)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    mensaje = ""
    if request.method == 'POST':
        correo = request.form.get('correo')
        password = request.form.get('password')
        if Usuario.query.filter_by(correo=correo).first():
            mensaje = "El correo ya está registrado"
        else:
            nuevo = Usuario(correo=correo)
            nuevo.set_password(password)
            db.session.add(nuevo)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('registro.html', mensaje=mensaje)

@app.route('/index')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/encuesta', methods=['GET', 'POST'])
@login_required
def encuesta():
    mensaje = ""
    if request.method == 'POST':
        nueva = Encuesta(
            nombre=request.form['nombre'],
            respuesta1=request.form.get('pregunta1'),
            respuesta2=request.form.get('pregunta2'),
            respuesta3=request.form.get('pregunta3'),
            respuesta4=request.form.get('pregunta4'),
            respuesta5=request.form.get('pregunta5')
        )
        db.session.add(nueva)
        db.session.commit()
        mensaje = "Encuesta guardada correctamente"
    return render_template('encuesta.html', mensaje=mensaje)

@app.route('/gestion')
@login_required
@solo_admin
def gestion():
    lista_usuarios = Usuario.query.all()
    return render_template('gestion.html', usuarios=lista_usuarios)

@app.route('/eliminar_usuario/<int:id>')
@login_required
@solo_admin
def eliminar_usuario(id):
    if current_user.id == id:
        flash("No puedes eliminarte a ti mismo.", "error")
        return redirect(url_for('gestion'))
    usuario_a_borrar = Usuario.query.get_or_404(id)
    db.session.delete(usuario_a_borrar)
    db.session.commit()
    flash("Usuario eliminado correctamente.", "success")
    return redirect(url_for('gestion'))

@app.route('/resultados')
@login_required
@solo_admin
def resultados():
    encuestas = Encuesta.query.all()
    return render_template('resultados.html', encuestas=encuestas)

@app.route('/eliminar/<int:id>')
@login_required
@solo_admin
def eliminar(id):
    encuesta = Encuesta.query.get_or_404(id)
    db.session.delete(encuesta)
    db.session.commit()
    flash("Encuesta eliminada correctamente.", "success")
    return redirect(url_for('resultados'))

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@solo_admin
def editar(id):
    encuesta = Encuesta.query.get_or_404(id)
    if request.method == 'POST':
        encuesta.nombre = request.form['nombre']
        encuesta.respuesta1 = request.form['respuesta1']
        encuesta.respuesta2 = request.form['respuesta2']
        encuesta.respuesta3 = request.form['respuesta3']
        encuesta.respuesta4 = request.form['respuesta4']
        encuesta.respuesta5 = request.form['respuesta5']
        db.session.commit()
        flash("Encuesta editada correctamente.", "success")
        return redirect(url_for('resultados'))
    return render_template('editar.html', encuesta=encuesta)

@app.route("/que_es")
@login_required
def que_es():
    return render_template("que_es.html")

@app.route("/residuos")
@login_required
def residuos():
    return render_template("residuos_y_contenedores.html")

@app.route("/beneficios")
@login_required
def beneficios():
    return render_template("beneficios.html")

@app.route("/ideas")
@login_required
def ideas():
    return render_template("ideas.html")

@app.route("/reciclaje")
@login_required
def reciclaje():
    return render_template("reciclaje.html")

@app.route("/consecuencias")
@login_required
def consecuencias():
    return render_template("consecuencias.html")

if __name__ == "__main__":
    app.run(debug=True)
