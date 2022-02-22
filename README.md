
The application is a rest API service that authenticate users based on the token provided 
 the user login will be provided with a token that can be used acros all other application within the Organisations 


to install 
python -m venv env
.\env\Scripts\activate
pip install -r requirements.txt

python app.py

 the application will generate a database migrations using the model user class
 
 the application as 7 endpoint 
  api/vi/
  the home accesed by every one 
 
api/v1/login
accesed by every one 

api/v1/user
accesed by autheticated users

then module life
by only Admins

api/vi/bank
only Agents

**api/vi/Home** 
 `only supervisor `


example to generate user
{
    "email":"most@email.com",
    "name":"metter",
    "password":"mettermost",
    "role":"AGENT"
}