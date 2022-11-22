from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


app = Flask(__name__)
cors = CORS(app)


app.config["JWT_SECRET_KEY"] = "Es-un-secreto"  # Mandar al config
jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401


@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePersmiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401


def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url


def validarPermiso(endPoint, metodo, idRol):
    url = dataConfig["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if ("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso


###################################################################################
#Mesas
@app.route("/mesas", methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>",methods=['GET'])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/mesas",methods=['POST'])
def crearMesas():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/<string:id>",methods=['PUT'])
def modificarMesas(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas/'+id
    response = requests.put(url, headers=headers, json=data)
    json= response.json()
    return jsonify(json)
@app.route("/mesas/<string:id>", methods=['DELETE'])
def eliminarMesas(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/<string:id>/departamentos/<string:id_departamento>",methods=['PUT'])
def asignarDepartamentoMesa(id,id_departamento):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas/'+id+'/departamentos/'+id_departamento
    response = requests.put(url, headers=headers)
    json= response.json()
    return jsonify(json)

#######################################################################
#Candidato
@app.route("/candidatos",methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
#
@app.route("/candidatos/<string:id>",methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/candidatos",methods=['POST'])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/candidatos/<string:id>",methods=['PUT'])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/candidatos/<string:id>", methods=['DELETE'])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/candidatos/<string:id>/partidos/<string:id_partido>",methods=['PUT'])
def asignarPartido(id,id_partido):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/'+id+'/partidos/'+id_partido
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)
#######################################################################
#Departamento
@app.route("/departamentos",methods=['GET'])
def getDepartamentos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/departamentos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/departamentos/<string:id>",methods=['GET'])
def getDepartamento(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/departamentos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/departamentos",methods=['POST'])
def crearDepartamento():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/departamentos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/departamentos/<string:id>",methods=['PUT'])
def modificarDepartamento(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/departamentos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/departamentos/<string:id>", methods=['DELETE'])
def eliminarDepartamento(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/departamentos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
######################################################################
#Resultados
@app.route("/resultados",methods=['GET'])
def getResultado():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/<string:id>",methods=['GET'])
def getResultados(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados",methods=['POST'])
def crearResultados():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/<string:id>",methods=['PUT'])
def modificarResultados(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/<string:id>", methods=['DELETE'])
def eliminarResultados(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/<string:id>/mesas/<string:id_mesa>/candidatos/<string:id_candidato>",methods=['PUT'])
def asignarRelacion(id,id_mesa,id_candidato):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/'+id+'/mesas/'+id_mesa+'/candidatos/'+id_candidato
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)
########################################################################
#Reportes resultados

#suma de votos de candidatos
@app.route("/resultados/votos",methods=['GET'])
def getSumaVotosCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/votos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

#suma de votos de las mesas
@app.route("/resultados/mesas",methods=['GET'])
def getSumaVotosMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

#suma de votos por partidos
@app.route("/resultados/partidos",methods=['GET'])
def getVotosPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/partidos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

#congreso
@app.route("/resultados/congreso",methods=['GET'])
def getCongreso():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/congreso'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
########################################################################
#Partidos
@app.route("/partidos",methods=['GET'])
def getPartido():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/<string:id>",methods=['GET'])
def getPartidos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/partidos",methods=['POST'])
def crearPartidos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/<string:id>",methods=['PUT'])
def modificarPartidos(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/<string:id>", methods=['DELETE'])
def eliminarPartidos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

##########################################################################
#Usuarios
@app.route("/usuarios",methods=['GET'])
def getUsuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>",methods=['GET'])
def getUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios",methods=['POST'])
def crearUsuarios():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>",methods=['PUT'])
def modificarUsuarios(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>", methods=['DELETE'])
def eliminarUsuarios(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>/rol/<string:id_rol>",methods=['PUT'])
def asignarRolUsuario(id,id_rol):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id+'/rol/'+id_rol
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)
#############################################################################
#Permisos
@app.route("/permisos",methods=['GET'])
def getPermisos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos/<string:id>",methods=['GET'])
def getPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos",methods=['POST'])
def crearPermisos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/permisos/<string:id>",methods=['PUT'])
def modificarPermisos(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/permisos/<string:id>", methods=['DELETE'])
def eliminarPermisos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
########################################################################
#Roles
@app.route("/roles",methods=['GET'])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/roles/<string:id>",methods=['GET'])
def getRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/roles",methods=['POST'])
def crearRoles():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/roles/<string:id>",methods=['PUT'])
def modificarRol(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/roles/<string:id>", methods=['DELETE'])
def eliminarRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

######################################################################
#Permisos roles
@app.route("/permisos-roles",methods=['GET'])
def getPermisosRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos-roles/rol/<string:id>/permiso/<string:id_permiso>",methods=['POST'])
def crearPermisosRoles(id, id_permiso):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/rol/'+id+'/permiso/'+id_permiso
    response = requests.post(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos-roles/<string:id>",methods=['GET'])
def getPermisosRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos-roles/<string:id>/rol/<string:id_rol>/permiso/<string:id_permiso>",methods=['PUT'])
def modificarPermisoRol(id,id_rol,id_permiso):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/'+id+'/rol/'+id_rol+'permiso'+id_permiso
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos-roles/<string:id>", methods=['DELETE'])
def eliminarPermisoRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/",methods=['GET'])
def test():
    json = {}
    json["message"]="Server running ..."
    return jsonify(json)
def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data
if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])