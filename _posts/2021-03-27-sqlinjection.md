---
layout: post
author: tourpran
title: SQL Injection
categories: Blogs
tags: [sql, Injection, SQLI]
---

### What is a Database:
A database can be thought as a collection of data in an organised manner. When companies have huge amounts of data to be stored, using databases is the key for efficient usage of the data. 

![](/assets/images/databasepic.png)

### SQL: 
SQL or Structured Query Language is just a way to talk to the database and manipulate the data by the program. In most Database management systems SQL language is used. This blog post is divided into ``basics of sql`` and ``exploitation of sql``.

### SQL Basics:

#### Creating a Database:

In order to follow this blog post it'll be helpfull to have mysql installed. First we will create and use a Database in mysql called testdb. Now this database can use used to store multiple tables where each table can be used to store different types of datas. For example a login table can be used to store all usernames and passwords and a store website can use another table to store all their products and prices with it. 

![](/assets/images/databasecreation.png)

#### Creating tables: 

For the fun of it lets create a table called person since everyone has their own unique ``features``. By features I mean their name, height and weigth.

![](/assets/images/tablesexample.png)

#### Access the data:

Inorder to get the required data we use SELECT statements. when we have lines of select statements and commands to give to the databases we call them queries.

note: * means everything (all)

![](/assets/images/queryexample.png)

Here we are select everything present in the table called person.

When we have multiple number of objects in our table we can use a element present in each object that is unique. Most of the time our names our unique so we can access our object with the help of out name.

![](/assets/images/queryexample1.png)


#### Login system:

In our login system (which we will use to hack) we have used sql query to check if the user and password given my the user is correct. The pseudo code is given below:
```php
<?php

$sql = "SELECT id FROM admin WHERE username = '$myusername' and passcode = '$mypassword'";
$result = mysqli_query($db,$sql); # Send the sql query to DataBase
$row = mysqli_fetch_array($result,MYSQLI_ASSOC); # Fetchs a result row as a array

if($count != 0) {
	echo "Success! " # Tell the user the login creds were correct
}
else{
	echo "Invalid " # Tell the user the login creds were incorrect
}
?>
```

### Different Exploitation Techniques:

#### Simple login bypass:

We can see that there are 2 users in the table. Obviously in the real world application there wont be a table showing the credentials, inorder for learning purpose I have made them visible. Now lets check if there is a sql injection possible.


![](/assets/images/loginlocalhost.png)

![](/assets/images/sqllocalhosterror.png)

Now If you are following the blog correctly you would have already know that this error is due to the ' (single quote) I gave. So the query looks like 

```
SELECT id FROM admin WHERE username = '' ' and passcode = 'a'
```
The unmatched single quotes make the query break and thereby telling us there are chances for a SQLInjection. Also a point to note is, its not required to get an error every time to prove there is a SQL Injection. Infact in most real world applications you would be left with blind sql injections which doesnt give you any output (covered later in this blog).

So we will use basic boolean logic for the first attack. We will tell the SQL Query that the username is true and passcode is true. So this will return the entire table and mostly likely we will be logged in as the first user (extreme case, likely never happens). 

![](/assets/images/sqlsimplelogin1.png)
![](/assets/images/simpleloginsql2.png)

Here we can see I gained access as tourpran who is the first user. Also in the query I managed to say that ``username='' or TRUE`` which will always be true, same for the password.

We can also login as admin if we pass the following credentials.
```
UserName: admin
password: ' or 'a'='a

SELECT id FROM admin WHERE username = 'admin' and passcode = '' or 'a'='a'

or 

username: ' or '1'='1
password: ' or 'a'='a' and username='admin' ; #

SELECT id FROM admin WHERE username = '' or 'a'='a' and passcode = '' or 'a'='a' and username='admin' ; #'

# - comment the rest of the line
```
