require('dotenv').config()

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const app = express();
const port = 3000;
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json());


// Sqlite ting
const db = new sqlite3.Database('./db.sqlite');

db.serialize(function() {
  console.log('creating databases if they don\'t exist');
  db.run('create table if not exists users (userId integer primary key, username text not null, password text not null)');
});

// views mappen sættes som den der skal hentes filer fra
app.use(express.static(__dirname + '../views'))

// funktion til at tiføje brugere til databasen 
const addUserToDatabase = (username, password) => {
  bcrypt.hash(password, 10, function(err, hash) {
  db.run(
    'insert into users (username, password) values (?, ?)', 
    [username, hash], 
    function(err) {
      if (err) {
        console.error(err);
      }
    }
  );
})
};

// funktion til at finde bruger i databasen
const getUserByUsername = (userName) => {
  // Smart måde at konvertere fra callback til promise:
  return new Promise((resolve, reject) => {  
    db.all(
      'select * from users where userName=(?)',
      [userName], 
      (err, rows) => {
        if (err) {
          console.error(err);
          return reject(err);
        }
        return resolve(rows);
      }
    );
  })
}


// på indexsiden: hvis brugeren er logget ind og har en session så sendes man videre til dashboard, hvis ikke så sendes man videre til loginsiden 
app.get("/", (req, res) => {
    res.sendFile("login.html", { root: path.join(__dirname, "views") });
});

/*
// Et dashboard som kun brugere med 'loggedIn' = true i session kan se
app.get("/dashboard", (req, res) => {
  if (req.session.loggedIn) {
    // Her generere vi en html side med et brugernavn på (Tjek handlebars.js hvis du vil lave fancy html på server siden)
    res.setHeader("Content-Type", "text/html");
    res.write("Welcome " + req.session.username + " to your dashboard");
    res.write('<a href="/logout">Logout</a>')
    return res.end();
  } else {
    return res.redirect("/");
  }
});
*/


app.post("/authenticate", bodyParser.urlencoded(), async (req, res) => {
  
  // Henter vi brugeren ud fra databasen
  const user = await getUserByUsername(req.body.username);
  const token = jwt.sign({user}, process.env.ACCESS_TOKEN_SECRET);

  console.log(token);

  if(user.length === 0) {
    console.log('no user found');
    return res.redirect("/");
  }

  // Tjekker om brugeren findes i databasen og om passwordet er korrekt
  let match = bcrypt.compareSync(req.body.password, user[0].password)

  if (match === true) {
    res.cookie("token", token, {
      httpOnly: true,
      // secure: true
      maxAge: 2592000,
      // signed: true
    }).sendFile("index.html", { root: path.join(__dirname, "views") });
    
  } else {
    // Sender en error 401 (unauthorized) til klienten
    console.log('fejl')
    return  res.sendStatus(401);
  }
});
  /*

  {
    
      //res.cookie("token", token, {
      // httpOnly: true,
      // secure: true
      // maxAge: 10000,
      // signed: true
      // });
      res.redirect("/protected");
      res.json({
        token: token
      })
      res.redirect("/protected");
      
    
  } else {
      // Sender en error 401 (unauthorized) til klienten
      console.log('fejl')
      return  res.sendStatus(401);
    
  }
  */ 


function ensureToken(req, res , next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined' ) {
      const bearer = bearerHeader.split(" "); 
      const bearerToken = bearer[1]; 
      req.token = bearerToken; 
      console.log(req.token)
      console.log(bearerToken)
      next() 
  } else {
      res.sendStatus(403); 

  }
}

app.get('/protected', ensureToken, (req, res) => {
  jwt.verify(req.token, process.env.ACCESS_TOKEN_SECRET, function(err, data) {
      if (err) {
          res.sendStatus(403)
      } else {
          res.json({
              message: 'Dette er beskyttet',
              data: data
          });
      }
  });
}); 



app.get("/logout", (req, res) => {
  req.session.destroy((err) => {});
  return res.send("Thank you! Visit again");
});


app.get("/signup", (req, res) => {
  
      return res.sendFile("signup.html", { root: path.join(__dirname, "views") });

});

app.post("/signup", bodyParser.urlencoded(), async (req, res) => {
  const user = await getUserByUsername(req.body.username)
  if (user.length > 0) {
    return res.send('Username already exists');
  }

  // Opgave 2
  // Brug funktionen hashPassword til at kryptere passwords (husk både at hash ved signup og login!)
  addUserToDatabase(req.body.username, req.body.password);
  res.redirect('/');
})  

app.listen(port, () => {
  console.log("Website is running");
});

