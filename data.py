from pymongo import MongoClient

# mongo_uri = "mongodb://localhost:27017/"
mongo_uri = "mongodb+srv://21bce199:0QgEXSavSModeGGr@cluster0.dtduv.mongodb.net/"

database_name = "MAP"
collection_item = "items"


client_atlas = MongoClient(mongo_uri)
database = client_atlas[database_name]
collection = database[collection_item]

arr = [
    {
        "id": 1,
        "name": "Tea",
        "price": 12,
        "category": "Snacks"
    },
    {
        "id": 2,
        "name": "Coffee",
        "price": 14,
        "category": "Snacks"
    },
    {
        "id": 3,
        "name": "Khamman",
        "price": 23,
        "category": "Snacks"
    },
    {
        "id": 4,
        "name": "Samosa",
        "price": 23,
        "category": "Snacks"
    },
    {
        "id": 5,
        "name": "Bread Roll",
        "price": 20,
        "category": "Snacks"
    },
    {
        "id": 6,
        "name": "Cheese Roll",
        "price": 28,
        "category": "Snacks"
    },
    {
        "id": 7,
        "name": "Gulab Jamun",
        "price": 30,
        "category": "Sweets"
    },
    {
        "id": 8,
        "name": "Kala Jamun",
        "price": 40,
        "category": "Sweets"
    },
    {
        "id": 9,
        "name": "Bread Butter",
        "price": 20,
        "category": "Sandwiches"
    },
    {
        "id": 10,
        "name": "Veg. Sandwich",
        "category": "Sandwiches",
        "price": 25
    },
    {
        "id": 11,
        "name": "Cheese Grill Sandwich",
        "price": 44,
        "category": "Sandwiches"
    },
    {
        "id": 12,
        "name": "Cheese Jam Sandwich",
        "price": 29,
        "category": "Sandwiches"
    },
    {
        "id": 13,
        "name": "Maska Bun",
        "price": 20,
        "category": "Sandwiches"
    },
    {
        "id": 14,
        "name": "Jam Bun",
        "price": 20,
        "category": "Sandwiches"
    },
    {
        "id": 15,
        "name": "Pizza",
        "price": 41,
        "category": "Sandwiches"
    },
    {
        "id": 16,
        "name": "Italian Pizza",
        "price": 100,
        "category": "Sandwiches"
    },
    {
        "id": 17,
        "name": "Burger",
        "price": 60,
        "category": "Sandwiches"
    },
    {
        "id": 18,
        "name": "Junglee Sandwich",
        "price": 80,
        "category": "Sandwiches"
    },
    {
        "id": 19,
        "name": "Upma",
        "price": 22,
        "category": "South Indian"
    },
    {
        "id": 20,
        "name": "Plain Dosa",
        "price": 26,
        "category": "South Indian"
    },
    {
        "id": 21,
        "name": "Tomato Uttapam",
        "price": 33,
        "category": "South Indian"
    },
    {
        "id": 22,
        "name": "Mix Uttapam",
        "price": 60,
        "category": "South Indian"
    },
    {
        "id": 23,
        "name": "Mendu Vada",
        "price": 28,
        "category": "South Indian"
    },
    {
        "id": 24,
        "name": "Mysore Plain Dosa",
        "price": 50,
        "category": "South Indian"
    },
    {
        "id": 25,
        "name": "Mysore Masala Ch. Dosa",
        "price": 75,
        "category": "South Indian"
    },
    {
        "id": 26,
        "name": "Curd",
        "price": 17,
        "category": "Curd & Juice"
    },
    {
        "id": 27,
        "name": "Cold Coffee",
        "price": 44,
        "category": "Curd & Juice"
    },
    {
        "id": 28,
        "name": "Butter-Milk",
        "price": 18,
        "category": "Curd & Juice"
    },
    {
        "id": 29,
        "name": "Jal-Jeera",
        "price": 18,
        "category": "Curd & Juice"
    },
    {
        "id": 30,
        "name": "Manchurian Dry",
        "price": 55,
        "category": "Chinese"
    },
    {
        "id": 31,
        "name": "Manchurian Gravy",
        "price": 61,
        "category": "Chinese"
    },
    {
        "id": 32,
        "name": "Manchurian Noodles",
        "price": 57,
        "category": "Chinese"
    },
    {
        "id": 33,
        "name": "Fried Rice ",
        "price": 44,
        "category": "Chinese"
    },
    {
        "id": 34,
        "name": "Noodles",
        "price": 55,
        "category": "Chinese"
    },
    {
        "id": 35,
        "name": "Chinese Bhel",
        "price": 57,
        "category": "Chinese"
    },
    {
        "id": 36,
        "name": "Bhaji-Pav",
        "price": 50,
        "category": "Chat"
    },
    {
        "id": 37,
        "name": "Dabeli",
        "price": 20,
        "category": "Chat"
    },
    {
        "id": 38,
        "name": "Bhel",
        "price": 39,
        "category": "Chat"
    },
    {
        "id": 39,
        "name": "Chana Chat",
        "price": 23,
        "category": "Chat"
    },
    {
        "id": 40,
        "name": "Dahi Vada",
        "price": 25,
        "category": "Chat"
    },
    {
        "id": 41,
        "name": "Samosa Chat",
        "price": 39,
        "category": "Chat"
    },
    {
        "id": 42,
        "name": "Papdi Chat",
        "price": 50,
        "category": "Chat"
    },
    {
        "id": 43,
        "name": "Masala Pav",
        "price": 70,
        "category": "Chat"
    },
    {
        "id": 44,
        "name": "Aloo Muter",
        "price": 80,
        "category": "Punjabi"
    },
    {
        "id": 45,
        "name": "Jeera Aloo",
        "price": 80,
        "category": "Punjabi"
    },
    {
        "id": 46,
        "name": "Chana Masala",
        "price": 80,
        "category": "Punjabi"
    },
    {
        "id": 47,
        "name": "Mix Veg.",
        "price": 85,
        "category": "Punjabi"
    },
    {
        "id": 48,
        "name": "Veg. Kolhapuri",
        "price": 85,
        "category": "Punjabi"
    },
    {
        "id": 49,
        "name": "Veg. Singapuri",
        "price": 85,
        "category": "Punjabi"
    },
    {
        "id": 50,
        "name": "Veg. Makkhanvala",
        "price": 95,
        "category": "Punjabi"
    },
    {
        "id": 51,
        "name": "Paneer Butter Masala",
        "price": 120,
        "category": "Punjabi"
    },
    {
        "id": 52,
        "name": "Paneer Tikka Masala",
        "price": 120,
        "category": "Punjabi"
    },
    {
        "id": 53,
        "name": "Paneer Bhurji",
        "price": 120,
        "category": "Punjabi"
    },
    {
        "id": 54,
        "name": "Ch. Butter Masala",
        "price": 120,
        "category": "Punjabi"
    },
    {
        "id": 55,
        "name": "Paneer Handi",
        "price": 120,
        "category": "Punjabi"
    },
    {
        "id": 56,
        "name": "Dal Fry",
        "price": 60,
        "category": "Punjabi"
    },
    {
        "id": 57,
        "name": "Dal Tadka",
        "price": 65,
        "category": "Punjabi"
    },
    {
        "id": 58,
        "name": "Jeera Rice",
        "price": 50,
        "category": "Punjabi"
    },
    {
        "id": 59,
        "name": "Veg. Biryani",
        "price": 70,
        "category": "Punjabi"
    },
    {
        "id": 60,
        "name": "Hyderabadi Biryani",
        "price": 70,
        "category": "Punjabi"
    },
    {
        "id": 61,
        "name": "Tava Roti",
        "price": 8,
        "category": "Punjabi"
    },
    {
        "id": 62,
        "name": "Tandoori Roti",
        "price": 15,
        "category": "Punjabi"
    },
    {
        "id": 63,
        "name": "Naan",
        "price": 25,
        "category": "Punjabi"
    }
]

collection.insert_many(arr)
print("Database created")

# Verify that the items are inserted correctly
print("Inserted items:")
# for item in collection.find({}):
#     print(item,'hey')