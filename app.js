//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/usersDB", { useNewUrlParser: true,  useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
  email : String,
  password : String
});

const secret = "ThisismyLittlePassword";
userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password'] });

const User = new mongoose.model("User", userSchema);

app.route("/")

  .get((req, res) => {
    res.render("home");
  });

app.route("/login")

  .get((req, res) => {
    res.render("login");
  })

  .post((req, res) => {
    const email = req.body.username;
    const password = req.body.password;
    User.findOne({email : email}, (err, foundUser) => {
      if(!err){
        if (foundUser) {
          if (foundUser.password === password) {
            res.render("secrets");
          }
        }
      } else{
        console.log(err);
      }
    })
  });

app.route("/register")

  .get((req, res) => {
    res.render("register");
  })

  .post((req , res) => {
    const newUser = new User({
      email : req.body.username,
      password : req.body.password
    });

  newUser.save((err) => {
    if(!err){
      res.render("secrets");
    }
  });
});


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
