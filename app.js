const express = require ('express');
const app = express();
const userModel = require('./models/user');
const postModel = require('./models/post');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json()); // To parse JSON request bodies
app.use(express.urlencoded({extended:true})); // To parse URL-encoded request bodies
app.set('view engine','ejs');
app.use(cookieParser());

app.get('/',(req,res)=>{
    res.render("index");
});

app.post('/register', async (req,res) => {
    let {username,email,name,password,age} = req.body;
    let user = await userModel.findOne({email})
    if (user) return res.status(500).send("User already registered");

    bcrypt.genSalt(10,(err,salt) => {
        bcrypt.hash(password,salt, async (err,hash) => {
           let user = await userModel.create({
                username,
                name,
                age,
                email,
                password:hash
            });
            let token = jwt.sign({email:email , userid:user._id},"shhh");
            res.cookie("token",token);
            res.send("registered");
        })
    })


    });


app.listen(3000);