from pymongo import MongoClient
from flask import Flask,jsonify
import json
import requests
from bson import json_util
from flask_restful import Api, Resource, reqparse, request
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
api = Api(app)

mongo_uri = "mongodb+srv://21bce199:0QgEXSavSModeGGr@cluster0.dtduv.mongodb.net/"
# mongo_uri = "mongodb://localhost:27017/"
database_name = "MAP"

# Connect to MongoDB Atlas
client = MongoClient(mongo_uri)

# Access the specified database and collection
database = client[database_name]
collection_order = database["orders"]
collection_orderhistories = database["orderhistories"]

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


# Define the Order and OrderHistory classes
class Order(Resource):
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

            total = 0
            item = []
            for obj in cursor:
                tt = {
                    "name":obj["name"],
                    "id":obj["id"],
                    "count":obj["count"],
                    "price":obj["price"]
                }
                item.append(tt)
                price_type = type(obj["price"])
                count_type = type(obj["count"])
                # print(f'Type of obj["price"]: {price_type}')  # Debug print
                # print(f'Type of obj["count"]: {count_type}')  # Debug print
                tmp1 = obj["count"]
                tmp2 = obj["price"]
                tmp4 = int(tmp1)
                tmp3 = int(tmp2)
                total += (tmp4*tmp3)
            
            collection_orderhistories.insert_one({"email":email, "items":item, "Amount":total})
            collection_order.delete_many({"email":email})
            return {"Total Amount": total}, 200
        else:
            return "Invalid"

class GetOrder(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email")
        args = parser.parse_args()

        email = args["email"]
        token = request.headers.get('x-access-token')

        if checkLogin(email,token):
        # if True:
            cursor = collection_orderhistories.find({"email":email})
            cursor = json.loads(json_util.dumps(cursor))
            return cursor,200
        else:
            return "Invalid"


# Define API endpoints
api.add_resource(Order, "/order/addOrder")
api.add_resource(GetOrder, "/order/getOrder")
app.run(host='0.0.0.0', port=3002, debug=True)