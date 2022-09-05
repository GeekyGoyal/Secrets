require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

/////////// Encryption ///////////
// const encrypt = require("mongoose-encryption");

/////////// Hashing ///////////
// const md5 = require("md5");

/////////// Bcrypt ///////////
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

/////////// Passport ///////////
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

/////////// Google O-Auth 2.0 ///////////
const GoogleStrategy = require('passport-google-oauth20').Strategy;

/////////// Mongoose findOrCreate ///////////
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

/////////// Passport ///////////
app.use(
  session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false,
    // cookie: { secure: true },
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: [{type:String}]
});

/////////// Passport ///////////
userSchema.plugin(passportLocalMongoose);

/////////// Mongoose findOrCreate ///////////
userSchema.plugin(findOrCreate);

/////////// Encryption ///////////
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

/////////// Passport ///////////
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user);
});
 
passport.deserializeUser(function(user, done) {
  done(null, user);
});


/////////// Google O-Auth 2.0 ///////////
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


app.get("/", function (req, res) {
  res.render("home");
});

/////////// Google O-Auth 2.0 ///////////
app.get("/auth/google",
  passport.authenticate("google", { scope: ['profile'] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

/*
app.post("/register", function(req, res) {
    
    /////////// Bcrypt ///////////
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email: req.body.username,
            password: hash
        });
        newUser.save(function(err) {
            if(err) {
                console.log(err);
            }
            else {
                res.render("secrets");
            }
        });
    });


    /* 
    const newUser = new User({
        email: req.body.username,
        password: req.body.password

        /////////// Hashing /////////// 
        // password: md5(req.body.password)
    });
    newUser.save(function(err) {
        if(err) {
            console.log(err);
        }
        else {
            res.render("secrets");
        }
    });
    
}); */

/* 
app.post("/login", function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    /////////// Hashing /////////// 
    // const password = md5(req.body.password);

    User.findOne({email: username}, function(err, foundUser) {
        if(err) {
            console.log(err);
        }
        else {
            if(foundUser) {

                /* if(foundUser.password === password) {
                    res.render("secrets");
                } */

/////////// Bcrypt ///////////
/*
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    if(result === true) {
                        res.render("secrets");
                    }
                });
            }
        }
    });
}); */

/////////// Passport ///////////

app.get("/secrets", function (req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUsers) {
    if(err) {
      console.log(err);
    }
    else {
      if(foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    }
  });
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

  User.findById(req.user._id.toString(), function(err, foundUser) {
    if(err) {
      console.log(err);
    }
    else {
      if(foundUser) {
        foundUser.secret.push(submittedSecret);
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function (req, res) {
  req.logout((err) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function () {
  console.log("Server Started on Port 3000");
});
