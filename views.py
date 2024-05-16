from flask import Blueprint, request, jsonify, render_template, redirect, url_for, make_response
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
import os
import json

bp = Blueprint('views', __name__)

@bp.route('/')
def home():
    return render_template('home.html')


@bp.route('/login-html', methods=['GET','POST'])
def login_form():
    from app import mongo
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = mongo.db.users.find_one({'email': email, 'password': password})
        if user:
            access_token = create_access_token(identity=str(user['_id']))
            response = make_response(jsonify({"access_token": access_token}), 200)
            response.set_cookie('jwt', access_token, httponly=True)
            return response
        else:
            return jsonify({"msg": "Bad username or password"}), 401
    else:
        return render_template('login.html')

@bp.route('/login', methods=['POST'])
def login():
    from app import mongo
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = mongo.db.users.find_one({'email': email, 'password': password})
    if user:
        access_token = create_access_token(identity=str(user['_id']))
        response = make_response(jsonify({"access_token": access_token}), 200)
        response.set_cookie('jwt', access_token, httponly=True)
        return response
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@bp.route('/staff-json', methods=['POST'])
@jwt_required()
def staff_json():
    from app import mongo
    position_filter = request.args.get('position')
    if position_filter:
        staff = list(mongo.db.staff.find({'position': position_filter}))
    else:
        staff = list(mongo.db.staff.find())

    for member in staff:
        member['_id'] = str(member['_id'])

    return jsonify(staff), 200

@bp.route('/staff', methods=['GET'])
@jwt_required()
def staff():
    from app import mongo
    position_filter = request.args.get('position')
    if position_filter:
        staff = list(mongo.db.staff.find({'position': position_filter}))
    else:
        staff = list(mongo.db.staff.find())

    staff_transformed = [
        {key: (str(value) if isinstance(value, ObjectId) else value) for key, value in member.items()}
        for member in staff
    ]

    return render_template('read.html', staff=staff_transformed)

@bp.route('/staff/create', methods=['GET', 'POST'])
@jwt_required()
def create_staff():
    from app import mongo
    if request.method == 'POST':
        try:
            data = json.loads(request.form.get('jsondata'))
            mongo.db.staff.insert_one(data)
            return redirect(url_for('views.staff'))
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format"}), 400

    else:
        return render_template('addone.html')
    

@bp.route('/staff/create-wjson', methods=['POST'])
@jwt_required()
def create_staffjson():
    from app import mongo
    data = request.json
    result = mongo.db.staff.insert_one(data)
    return jsonify({"msg": "Staff member created successfully", "staff_id": str(result.inserted_id)}), 201

@bp.route('/staff/<string:staff_name>', methods=['GET'])
@jwt_required()
def staff_member(staff_name):
    from app import mongo
    staff = list(mongo.db.staff.find({'name': staff_name}))
    if staff:
        staff_transformed = [
            {key: (str(value) if isinstance(value, ObjectId) else value) for key, value in member.items()}
            for member in staff
        ]

        return render_template('member.html', staff=staff_transformed)
    else:
        return jsonify({"msg": "Staff member not found"}), 404

@bp.route('/staff/<string:staff_id>/delete', methods=['GET','POST'])
@jwt_required()
def staff_delete(staff_id):
    from app import mongo
    if request.method == 'POST':
        result = mongo.db.staff.delete_one({'_id': ObjectId(staff_id)})
        if result.deleted_count:
            return jsonify({"msg": "Staff member deleted successfully"}), 200
        else:
            return jsonify({"msg": "Staff member not found"}), 404
    else:
        return render_template('delete.html', staff_id=staff_id)


@bp.route('/upload', methods=['GET', 'POST'])
@jwt_required()
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('upload.html', message="No file part")
        
        file = request.files['file']
        if file.filename == '':
            return render_template('upload.html', message="No selected file")
        
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join('uploads', filename))
            return render_template('upload.html', message="File uploaded successfully, Filename: " + filename)
        
        return render_template('upload.html', message="File not allowed")
    else:
        return render_template('upload.html')

@bp.route('/logout', methods=['GET','POST'])
@jwt_required()
def logout():
    response = make_response(jsonify({"msg": "Logged out successfully"}), 200)
    response.set_cookie('jwt', '', expires=0)  # Clear the JWT cookie
    return response
