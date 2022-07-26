# computer-security-finalproject

Password Manager

This code works as a simple password manager by means of [Argon2]( https://pypi.org/project/argon2-cffi/)  hashing, with [ChaCha20]( https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20.html)  encoding using a password resulting key created with [Scrypt]( https://cryptobook.nakov.com/mac-and-key-derivation/scrypt)  from a master and a login passwords. 
 

How it Works:

#First run

    Running the code for the first time, or each time the database is deleted, it is mandate to create two passwords for encryption password and login password respectively. Of which, the login password will be stored in database. This acknowledges you to protect passwords encrypted with different master passwords while keeping them only to yourself.

#Once the database is created
    
Now that the database is created, *login password* will be necessary whenever you want to access it.

At login you will be asked the master password also, in case you want to process a password (encrypt a new one or decrypt an existing one).
    
> **!! Attention !!**  

Master password is inquired as it were at login so in case you've got passwords scrambled with a master varied from the one you fair given you won’t be able to decode them. Hence, It is very important to be cautious in consideration to what passwords you'll need to get to scramble or unscramble when giving the master password at login.

#Needed modules

A separate file, requirement.txt, is being provided in the folder mentioning all the dependencies and modules required for this application to work successfully.

#Images 

First time login
 ** /Images/First_time_login.png

Login
 **Images/Login.png

Menu
 **Images/Menu.png

Add password
 **Images/Add_password.png

Retrieve password
 **Images/Retrieve_password.png

Edit Menu
 **Images/Edit_Menu.png

List all services
 **Images/List_all_services.png

Database
 **Images/Database_project.png

Hash Table
 **Images/Hash_table.png

Login Table
 **Images/Login_table.png
