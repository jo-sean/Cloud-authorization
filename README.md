# cs493_hw7
More Authentication and Authorization


Instructions
For this assignment you need only deal with boats

{ 
 "id": 123,                 # Automatically generated by Datastore
 "name": "Sea Witch",       # String. The name of the boat.
 "type": "Catamaran",       # String. The type of the boat, power boat, catamaran etc.
 "length": 28,              # Integer. The length of the boat.
 "public": true,            # Boolean. true if the boat is public, false if it's private.
 "owner": "auth0|5eb70257", # The boat's owner, value of sub property in the JWT
 "self":"https://appspot.com/boats/123" # Optional
}
The new properties here are

owner
Each boat has an owner which corresponds to the value of the "sub" property in the JWT when the boat is created.
public
A Boolean value
If the value is true, then the boat is public
If false, then the boat is private
The self property is no longer required. If it is easier for you, leave it in. Its presence or absence, or its value will have no impact on your grade.

REST API
Here are the REST API endpoints you need to implement (note you don't need to implement editing the boat or viewing an individual boat)

POST /boats
If the request has a valid JWT, create the boat, return 201 status and set the owner of the boat to the value of the sub property in the JWT.
For missing or invalid JWTs, return 401 status code.
The request body will be a JSON object with the properties
name
type
length
public
You can assume that the request body is valid and you don't need to validate it.
You don't need to enforce uniqueness of the name.
GET /owners/:owner_id/boats
Return 200 status code and an array with all public boats for the specified owner_id regardless of whether the request has a valid or invalid JWT or whether a
JWT is missing.
If this owner doesn't have any public boats, return status code 200 and an empty array.
You do not need to implement any of the parent routes
E.g. You do not need to implement GET /owners or GET /owners/:owner_id
Each boat in the response should be a JSON with at least the 6 required properties shown above.
The response must not be paginated.
GET /boats
If the supplied JWT is valid, return status code 200 and an array with all boats whose owner matches the sub property in the supplied JWT
If no JWT is provided or an invalid JWT is provided, return status code 200 and an array with all public boats regardless of owner.
Each boat is the response should be a JSON with at least the 6 required properties shown above.
The response must not be paginated.
DELETE /boats/:boat_id
Only the owner of a boat with a valid JWT should be able to delete that boat
If a boat exists with this boat_id and the JWT in the request is valid and the JWT belongs to the boat's owner, delete the boat and return 204 status code
Return 401 status code for missing or invalid JWTs.
Return 403 status code
If the JWT is valid but boat_id is owned by someone else, or
If the JWT is valid but no boat with this boat_id exists
JWT
In addition to the REST API, you also need to implement a web application that allows users to generate JWTs
You can use Auth0 or Google OAuth API as your JWT provider. To use some other JWT provider, you need to get approval from the instructors.
If you use Auth0 as your JWT provider
You need to provide a "Welcome" page on which the user can provide an email address and a password, and you need to register them at Auth0 under your Auth0 domain
After the account is created, the "User Info" page must display a JWT issued by Auth0 for this user
If the user has already created an account, when they enter the email address and the password on the "Welcome" page, you should display the "User Info" page 
with a new JWT issued by Auth0 for this user
Here are links to tutorials on Auth0 website about how to add functionality for user creation, login, logout, etc. to an application
For Node.js https://auth0.com/docs/quickstart/webapp/nodejs (Links to an external site.)
For Python https://auth0.com/docs/quickstart/webapp/python (Links to an external site.)
If you are unable to integrate your app with Auth0 for user creation, login, etc., you can pre-create 2 users in your Auth0 domain and provide their email 
and password in your PDF document for the loss of 0.5 points.
In this case, the grader must still be able to use your app to generate JWTs using the email and password info you have provided for these 2 users.
In this case, you can either support generation of JTWs via your web app or by providing a Postman Collection that contains a test that calls a REST endpoint
in your Auth0 domain to generate JWTs.
Recommendation: If you are using Auth0, we recommend that you start by creating 2 users and getting everything else working, before tacking the functionality
of integrating your app with Auth0 for user creation, etc.
If you use Google OAuth API as your JWT provider
You must not restrict the gmail.com address to oregonstate.edu, i.e., you must allow external users to use your app to generate JWTs.
You need to have a "Welcome" page which a link that takes user to Google's login page, and after they login to Google, then you need to display a "User Info" 
page with a new JWT issued by Google.
You don't need to display the state variable
FYI: the response you got from Google OAuth API that you used in Assignment 6 to get the auth token also includes the JWT in the attribute "id_token"
You are free to use Google OAuth libraries and are no longer required to code the OAuth flow yourself (like you had to do for Assignment 6).
If you are using the Google OAuth library, see the following link for sample code on how to verify the JWT
https://developers.google.com/identity/sign-in/web/backend-auth
