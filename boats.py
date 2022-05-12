from flask import Blueprint, request, make_response, jsonify
from google.cloud import datastore
import json
import constants
from json2html import *
from string import ascii_letters, whitespace
from google.oauth2 import id_token
from google.auth.transport import requests

client = datastore.Client()

bp = Blueprint('boat', __name__, url_prefix='/boats')


@bp.route('', methods=['POST', 'GET'])
def boats_get_post():
    if request.method == 'POST':
        if not request.is_json:
            # Checks if sent data is json, if not return 415
            err = {"Error": "The request header 'content_type' is not application/json "
                            "and/or the sent request body does not contain json"}
            res = make_response(err)
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 415
            return res

        elif 'application/json' not in request.accept_mimetypes:
            # Checks if client accepts json, if not return 406
            err = {"Error": "The request header ‘Accept' is not application/json"}
            res = make_response(err)
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 406
            return res

        # Checks if JWT was provided in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            auth_header = auth_header.split(" ")[1]
            # Checks validity of JWT provided
            try:
                sub = id_token.verify_oauth2_token(
                    auth_header, requests.Request(), constants.client_id)['sub']
            except:
                err = {"Error": "JWT is invalid and could not be verified"}
                res = make_response(json2html.convert(json=err))
                res.headers.set('Content-Type', 'text/html')
                res.status_code = 401
                return res
        else:
            err = {"Error": "Authorization header is missing"}
            res = make_response(json2html.convert(json=err))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 401
            return res

        # Checks if sent data is json, if not return 415
        try:
            content = request.get_json()
        except:
            err = {"Error": "The request header 'content_type' is not application/json "
                            "and/or the sent request body does not contain json"}
            res = make_response(err)
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 415
            return res

        # Check contents of the json file to make sure keys have values, and it is not empty.
        # Only supported attributes will be used. Any additional ones will be ignored.
        if not content or "name" not in content or "type" not in content \
                or "length" not in content or "public" not in content:
            err = {"Error": "The request object is missing at least one of the required attributes"}
            res = make_response(err)
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        # Check value of contents to make sure they are not null or have valid characters.
        if set(content["name"]).difference(ascii_letters + whitespace) or \
                set(content["type"]).difference(ascii_letters + whitespace) \
                or not isinstance(content["length"], int):
            err = {"Error": "The request object has at least one invalid value assigned to an attribute"}
            res = make_response(err)
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        # Name of boat must be unique
        query = client.query(kind=constants.boats)
        boat_list = list(query.fetch())

        # Search all boat objects and compare the names to make sure they are unique
        for curr_boat in boat_list:
            if curr_boat["name"] == content["name"]:
                err = {"Error": "There is already a boat with that name"}
                res = make_response(err)
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 403
                return res

        # Create new boat entity
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
                         "length": content["length"], "public": content["public"], "owner": sub})
        client.put(new_boat)

        new_boat["id"] = new_boat.key.id
        new_boat["self"] = request.base_url + "/" + str(new_boat.key.id)

        res = make_response(json.dumps(new_boat))
        res.mimetype = 'application/json'
        res.status_code = 201
        return res

    elif request.method == 'GET':
        
    # If the supplied JWT is valid, return status code 200 and an array with all boats whose owner matches the sub property in the supplied JWT
    # If no JWT is provided or an invalid JWT is provided, return status code 200 and an array with all public boats regardless of owner.
    # Each boat is the response should be a JSON with at least the 6 required properties shown above.
    # The response must not be paginated.

        public = False
        sub = None
        # Checks if JWT was provided in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            auth_header = auth_header.split(" ")[1]
            # Checks validity of JWT provided
            try:
                sub = id_token.verify_oauth2_token(
                    auth_header, requests.Request(), constants.client_id)['sub']
            except:
                public = True
        else:
            public = True

        # Source: https://cloud.google.com/datastore/docs/concepts/queries
        # Sub of boat provided
        query = client.query(kind=constants.boats)
        if public:
            query.add_filter("public", "=", True)
        else:
            query.add_filter("owner", "=", sub)

        boat_list = list(query.fetch())

        for curr_boat in boat_list:
            curr_boat["id"] = curr_boat.key.id
            curr_boat["self"] = request.base_url + "/" + str(curr_boat.key.id)

        res = make_response(json.dumps(boat_list))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 404
        return res

    else:
        # Status code 405
        res = make_response()
        res.headers.set('Allow', 'GET, DELETE')
        res.headers.set('Content-Type', 'text/html')
        res.status_code = 405
        return res


@bp.route('/<bid>', methods=['DELETE'])
def boats_delete(bid):
    if request.method == 'DELETE':

        boat_key = client.key(constants.boats, int(bid))
        boat = client.get(key=boat_key)

        # Checks if boat with boat_id exists
        if not boat:
            err = {"Error": "No boat with this boat_id exists"}
            res = make_response(err)
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 403
            return res

        elif 'Authorization' not in request.headers:
            err = {"Error": "Authorization header is missing"}
            res = make_response(json2html.convert(json=err))
            res.headers.set('Content-Type', 'text/html')
            res.status_code = 401
            return res

        auth_header = request.headers['Authorization'][1]
        # Checks validity of JWT provided
        try:
            sub = id_token.verify_oauth2_token(
                auth_header, requests.Request(), constants.client_id)['sub']
        except:
            err = {"Error": "JWT is invalid and could not be verified"}
            res = make_response(json2html.convert(json=err))
            res.headers.set('Content-Type', 'text/html')
            res.status_code = 401
            return res

        if boat['owner'] != sub:
            err = {"Error": "This boat is owned by someone else"}
            res = make_response(err)
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 403
            return res
        else:
            client.delete(boat_key)
            res = make_response()
            res.status_code = 204
        return res

    else:
        # Status code 405
        res = make_response()
        res.headers.set('Allow', 'DELETE')
        res.headers.set('Content-Type', 'text/html')
        res.status_code = 405
        return res
