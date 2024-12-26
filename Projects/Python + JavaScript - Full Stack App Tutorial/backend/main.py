from flask import request, jsonify # jsonify: allows to return json data
from config import app, db 
from models import Contact 
# contains main route/endpoints
# we want CRUD app. so we want operation for Creating, Reading, Updating and Deleting.
# create
# - first_name
# - last_name
# - email

# when we create an API
# -x- we have server running the API
# -x- server has some address e.g. localhost:5000
# -x- localhost:5000/home, here endpoint is '/home'
# -x- when we hit/send request to an endpoint like 'localhost:5000/create_contact'/
# we also have to submit some data along side it. i.e. firstname/last/email

## Request
## type: DELETE # requests can have many type of METHODS e.g. GET request/POST request(where we are trying to create something new)
# e.g. when we create a new contact we use POST request
# PATCH request - used to update something
# DELETE request - used to delete something
## json: {}

## Response
## status: 404 # specifies if the request was successful e.g. 200(good) or 404 or 400(bad request) or 403(forbidden)
## json: {} # respond by sending back data in the form of json.

@app.route("/contacts", methods=["GET"]) # decorator - specifies what route we are gonna go to and the valid methods! i.e. we only want to use the GET method for the URL.
def get_contacts(): # specify how to handle GET request
    contacts = Contact.query.all() # get all the different contacts inside the db.

    # ISSUE: these are all python objects. We can't return python objects from our code. => what we can return instead is json data. 

    json_contacts = map(lambda x:x.to_json(), contacts)
    # -x- contacts is a list of our python objects.
    # -x- all the contact object have the 'to_json' method.
    # -x- map takes all elements from contacts list and applies function to them and returns back new list.
    # NOTE: lambda is a shortcut to making a function. It takes in 'x' as its parameter(which is basically each object from the list contacts) and applies 'x.to_json()' function to it and stores it into a new list. 
    # -x- map returns map object.
    json_contacts = list(json_contacts) # convert map object to list.
    return jsonify({"contacts": json_contacts})

@app.route("/create_contact", methods=["POST"])
def create_contact():
    first_name = request.json.get("firstName") # look through the json data inputed by the user through the front end of the website, and look for 'firstName' attribute.
    last_name = request.json.get("lastName") # if key dont exist it returns None.
    email = request.json.get("email")
    
    if not first_name or not last_name or not email:
        return (
            jsonify({"message": "You must include a first name, last name and email"}), 
            400,
        )
    # make a new contact add that to data base and tell user it worked!
    new_contact = Contact(first_name=first_name, last_name=last_name, email=email) # create python class.
    try: # errors can occur during this e.g. the email matches with another users email.(we specified UNIQUE=TRUE)
        db.session.add(new_contact) # in the staging area, not yet written to the database.
        db.session.commit() # written to db 
    except Exception as e: # catch any exception and return to user as json block.
        return jsonify({"message": str(e)}), 400 # status code 400 - error.

    return jsonify({"message":"User Created!"}), 201 # status code 201 - user created.(its a status code to say that an object has be created.)
@app.route("/update_contact/<int:user_id>", methods=["PATCH"]) # will look something like - /update_contact/2
def update_contact(user_id):
    contact = Contact.query.get(user_id)

    if not contact:
        return jsonify({"message":"User not found"}), 404
    
    data = request.json
    contact.first_name = data.get("firstName", contact.first_name) # NOTE the 'get' will look in 'data' to see if dictionary key 'firstName' has any attached values(if it does, it updates 'contact.first_name' with that value). If not it will default to 'contact.first_name' as specified after the comma and update 'contact.first_name' with 'contact.first_name'.
    contact.last_name = data.get("lastName", contact.last_name)
    contact.email = data.get("email", contact.email)

    db.session.commit()

    return jsonify({"message":"User updated"}), 200

@app.route("/delete_contact/<int:user_id>", methods=["DELETE"])
def delete_contact(user_id):
    contact = Contact.query.get(user_id)

    if not contact:
        return jsonify({"message":"User not found"}), 404
    
    db.session.delete(contact)
    db.session.commit()

    return jsonify({"message":"User deleted!"}), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all() # go ahead and create all the different models we defined in database. 
        # we gotta make the database if its not already made i.e. the first time we run it.
    
    app.run(debug=True) # run all endpoints and api