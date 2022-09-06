require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
//Level 2
//const encrypt = require("mongoose-encryption");
//Level 3
//const MD5 = require("md5");
//level 4
//const bcrypt = require("bcrypt");
//const saltRounds = 10;
//Level 5
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
//Level 6
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");
app.use(express.static("public"));
//Sessions Level 5 Cookies
app.use(session({
    secret: "Our little Secret",
    resave: false,
    saveUninitialized: false
}));
//Passport Level 5 cookies
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    //google unique id passed to avoid creating multiple id level 6 Oauth 
    googleId: String,
    //store the secret
    secret:String
});
//database encrytion Level 2
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });
//Cookies Level 5
userSchema.plugin(passportLocalMongoose);
//findorcreate packages to run mongoose find and create function
userSchema.plugin(findOrCreate);
//add the plugin before creating the mongoose model
const User = new mongoose.model("User", userSchema);
//Serialize Level 5
passport.use(User.createStrategy()); 

/*Serialize locally Level 5
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
*/
//Serialize for to config other authentication like google
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user.id);
    });
});
passport.deserializeUser(function(id, cb) {
    process.nextTick(function() {
      User.findById(id, (err, user)=>{
        return cb(err, user)
      });
    });
});
//Level 6 OAuth for google using passport and google startegies
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //google+ api
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", (req, res) =>{
    res.render("home");
});
//google authentication page
app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] })
);
//our secrets page redirect origin after the signin
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
});
app.get("/login", (req,res) => {
    res.render("login");
});
app.get("/register", (req, res) => {
    res.render("register");
});
app.get("/secrets", (req, res) => {
    //check if our srcrets string exists and send it back to the secrets page
    User.find({"secret": {$ne: null}}, (err, foundUsers)=>{
        if(err){
            console.log(err);
        } else {
            if (foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});

            }
        }
    });
});
app.get("/logout", (req, res)=>{
    req.logOut(err => {
        if (err) {return next(err);}
    });
    res.redirect("/");
});
app.get("/submit", (req,res)=>{
    //to make sure the user is auhtenticated be4 using the secrets
    if(req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});


app.post("/register", (req,res)=>{
    /*
    Level 4
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            email: req.body.username,
            //store the password in an irreversible hash
            //password: MD5(req.body.password)
            password: hash
        });
        newUser.save(err=>{
            if (err){
                console.log(err);
            } else{
                res.render("secrets")
            }
        });
    });
    */
   //Level 5
   User.register({username: req.body.username}, req.body.password, (err, user)=>{
    if (err){
        console.log(err);
        res.redirect("/register");
    } else {
        passport.authenticate("local")(req, res, ()=>{
            res.redirect("/secrets");
        });
    }
   });
});
app.post("/login", (req,res)=>{
    /*
    Level 4
    const username = req.body.username;
    Level 3
    //const password = MD5(req.body.password);
    const password = req.body.password;

    User.findOne({email: username}, (err, foundUser)=>{
        if(err){
            console.log(err);
        } else {
            if (foundUser){
                //if (foundUser.password === password){
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    if (result === true){
                        res.render("secrets");
                    }
                });
            }
        }
    });
    */
   const user = new User({
    username: req.body.username,
    password: req.body.password
   });
   //uses passport
   req.login(user, (err)=>{
    if(err) console.log(err);
    else{
        passport.authenticate("local")(req,res, ()=>{
            res.redirect("/secrets");
        });
    }
   });
});
app.post("/submit", (req,res)=>{
    const submittedSecrets = req.body.secret;
    User.findById(req.user.id, (err, foundUser)=>{
        if(err){ 
            console.log(err);
        } else{
            if(foundUser) {
                foundUser.secret = submittedSecrets;
                foundUser.save(()=>{
                    res.redirect("/secrets");
                });
            }
        }
    });
});


app.listen("3000", () => {
    console.log("Server is live on port 3000!");
});