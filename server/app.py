#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()

        validation_rules = {
            "username": {
                "required": True,
                "message": "Username is required."
            },
            "password":{
                "required":True,
                "message": "Password is required."
            },
            "image_url": {
                "required": True,
                "message": "Image Url is required."
            },
            "bio":{
                "required": True,
                "message": "Bio is required."
            }
        }
        errors = []

        for field, rules in validation_rules.items():
            if rules.get("required") and not json.get(field):
                errors.append(rules["message"])
        
        if errors:
            response = {"errors": errors}
            return make_response(response, 422)

        user = User(
            username=json["username"],
            image_url=json["image_url"],
            bio=json["bio"]
        )
        user.password_hash = json["password"]

        try:
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            response = {"errors": [str(e)]}
            return make_response(response, 422)
        
        session["user_id"] = user.id

        return make_response(user.to_dict(rules=("-users.recipes",)), 201)

        


class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get("user_id")).first()
        if user:
            return make_response(user.to_dict(rules=("-users.recipes",)), 200)
        else:
            return make_response({
            "message": "Unauthorized access",
            }, 401)

class Login(Resource):
    def post(self):
        user = User.query.filter(User.username == request.get_json()["username"]).first()
        
        if user:
            if user.authenticate(request.get_json()["password"]):
                session["user_id"] = user.id
                return make_response(user.to_dict(rules=("-users.recipes",)), 200)
            else:
                return make_response({"error": "Invalid username/password"}, 401)
        else:
            return make_response({"error": "Invalid username/password"}, 401)

class Logout(Resource):
    def delete(self):
        if session.get("user_id"):
            session["user_id"] = None
            return {}, 204
        else:
            return {"message": "User not logged in."}, 401

class RecipeIndex(Resource):
    def get(self):
        recipes = Recipe.query.all()

        if session.get("user_id"):
            response = [recipe.to_dict() for recipe in recipes]
            return make_response(response, 200)
        else:
            return {"error": "Unauthorized access."}, 401
        
    def post(self):
        json = request.get_json()
        if session.get("user_id"):
                validation_rules = {
                    "title": {
                        "required": True,
                        "message": "Title is required."
                    },
                    "instructions":{
                        "required":True,
                        "message": "Instructions is required."
                    },
                    "minutes_to_complete": {
                        "required": True,
                        "message": "Minutes to Complete is required."
                    },
                }
                errors = []

                for field, rules in validation_rules.items():
                    if rules.get("required") and not json.get(field):
                        errors.append(rules["message"])
                
                if errors:
                    response = {"errors": errors}
                    return make_response(response, 422)
                
                try:
                    recipe = Recipe(
                    title=json["title"],
                    instructions=json["instructions"],
                    minutes_to_complete=json["minutes_to_complete"],
                    user_id = session["user_id"]
                    )
                    db.session.add(recipe)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    response = {"errors": [str(e)]}
                    return make_response(response, 422)
                
                return make_response(recipe.to_dict(), 201)
        else:
            return {"error": "Unauthorized Access"}, 401
    


        

            

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)