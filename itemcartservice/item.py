from pymongo import MongoClient
from flask import Flask,jsonify
import json
import requests
from bson import json_util
from flask_restful import Api, Resource, reqparse, request

app = Flask(__name__)
api = Api(app)


mongo_uri = "mongodb+srv://21bce199:0QgEXSavSModeGGr@cluster0.dtduv.mongodb.net/"
# mongo_uri = "mongodb://localhost:27017/"
database_name = "MAP"

# Connect to MongoDB Atlas
client = MongoClient(mongo_uri)

# Access the specified database and collection
database = client[database_name]
collection_item = database["items"]
collection_order = database["orders"]

# Verify database connection and collection access
print(f"Connected to database: {database_name}")
print(f"Items collection: {collection_item.name}")
print(f"Orders collection: {collection_order.name}")

def checkLogin(email, token):
    api_url = "http://auth:3003/auth/isLoggedIn"
    # Set the data you want to send in the POST request
    post_data = {
        "email": email
    }
    headers = {
        "x-access-token": token
    }

    response = requests.post(api_url, json=post_data, headers=headers)
    response = response.json()

    if response["auth"] == True:
        return True
    else:
        return False
    
class getMenu(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email")
        args = parser.parse_args()

        email = args["email"]
        token = request.headers.get('x-access-token')

        if checkLogin(email,token):
        # if True:
            cursor = collection_item.find({})
            return json.loads(json_util.dumps(cursor)), 200
        else:
            return "Invalid"


class addItemtoCart(Resource):
    def post(self):
        # Set up parser for expected arguments
        parser = reqparse.RequestParser()
        parser.add_argument("id")
        parser.add_argument("email")
        parser.add_argument("count")
        args = parser.parse_args()

        # Retrieve arguments
        email = args["email"]
        id = int(args["id"])
        count = args["count"]
        token = request.headers.get('x-access-token')

        print(f"Received request to add item with id: {id}, email: {email}, count: {count}")

        # Check user authentication
        if checkLogin(email, token):
            print(f"Login check passed for email: {email}")
            # Attempt to find the item in the collection
            print(id)
            cursor = collection_item.find_one({"id": id})
            if cursor:
                print(f"Item found in collection: {cursor}")
                # Convert MongoDB document to JSON-compatible dictionary
                item_data = json.loads(json_util.dumps(cursor))

                # Insert item into the order collection
                collection_order.insert_one({
                    "email": email,
                    "id": id,
                    "name": item_data.get("name"),
                    "count": count,
                    "price": item_data.get("price")
                })
                print(f"Item with id: {id} added to cart for email: {email}")
                return {"message": "Item Added"}, 200
            else:
                print(f"Item with id: {id} not found in collection")
                return {"message": f"Item not found {id}"}, 404
        else:
            print(f"Login check failed for email: {email}")
            return {"message": "Invalid"}, 401


class removeItemfromCart(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email")
        parser.add_argument("id")
        args = parser.parse_args()

        email = args["email"]
        id = int(args["id"])
        token = request.headers.get('x-access-token')

        if checkLogin(email, token):
            collection_order.delete_one({"id": id, "email": email})
            return {"message": "Item Removed"}, 200
        else:
            return {"message": "Invalid"}, 401

class updateIteminCart(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("id")
        parser.add_argument("email")
        parser.add_argument("count")
        args = parser.parse_args()

        email = args["email"]
        id = int(args["id"])
        count = int(args["count"])  # Ensure count is parsed as an integer
        token = request.headers.get('x-access-token')

        if checkLogin(email, token):
            collection_order.update_one({"id": id, "email": email}, {'$set': {"count": count}})
            return {"message": "Item Updated"}, 200
        else:
            return {"message": "Invalid"}, 401
    

class getCartItems(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email")
        args = parser.parse_args()

        email = args["email"]
        token = request.headers.get('x-access-token')

        if checkLogin(email,token):
        # if True:
            cursor = collection_order.find({"email":email})
            cursor = json.loads(json_util.dumps(cursor))
            return cursor,200
        else:
            return "Invalid"

api.add_resource(getMenu, '/item')
api.add_resource(addItemtoCart,'/item/addItem')
api.add_resource(removeItemfromCart, '/item/removeItem')
api.add_resource(updateIteminCart, '/item/updateItem')
api.add_resource(getCartItems, '/item/getCartItems')
app.run(host ='0.0.0.0', port = 3001, debug=True)