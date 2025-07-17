const express = require('express');
const app = express();
const userModel = require('./models/user'); // Assuming these models exist
const postModel = require('./models/post'); // Assuming these models exist
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json()); // To parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // To parse URL-encoded request bodies
app.set('view engine', 'ejs');
app.use(cookieParser());

app.get('/', (req, res) => {

    res.render("index");
});

app.get('/profile', isLoggedIn,async (req, res) => {
    let user = await userModel.findOne({email:req.user.email}).populate("posts");
    
    res.render("profile",{user});
});

app.get('/login', (req, res) => {
    res.render("login");
});


app.post('/post', isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({ email: req.user.email });
    let { content } = req.body;

    let post = await postModel.create({
        user: user._id,
        content,
    });

    user.posts.push(post._id);
    await user.save();

    res.redirect('/profile');
});


app.post('/register', async (req, res) => {
    let { username, email, name, password, age } = req.body;
    let user = await userModel.findOne({ email });
    if (user) return res.status(500).send("User already registered");

    bcrypt.genSalt(10, (err, salt) => {
        if (err) return res.status(500).send("Error generating salt."); // Added error handling
        bcrypt.hash(password, salt, async (err, hash) => {
            if (err) return res.status(500).send("Error hashing password."); // Added error handling
            try {
                let user = await userModel.create({
                    username,
                    name,
                    age,
                    email,
                    password: hash
                });
                let token = jwt.sign({ email: email, userid: user._id }, "shhh");
                res.cookie("token", token);
                res.send("registered");
            } catch (createError) {
                console.error("Error creating user:", createError);
                res.status(500).send("Error registering user.");
            }
        });
    });
});

app.post('/login', async (req, res) => {
    let { email, password } = req.body;
    let user = await userModel.findOne({ email });
    if (!user) return res.status(500).send("Something went wrong"); // Consider more specific message

    bcrypt.compare(password, user.password, function (err, result) {
        if (err) return res.status(500).send("Error comparing passwords."); // Added error handling
        if (result) {
            let token = jwt.sign({ email: email, userid: user._id }, "shhh");
            res.cookie("token", token);
            res.status(200).redirect("/profile");
        } else {
            res.redirect('/login');
        }
    });
});

app.get('/logout', (req, res) => {
    res.cookie("token", "", { maxAge: 0 }); // Clear the cookie effectively
    res.redirect("/login");
});

function isLoggedIn(req, res, next) {
    if (req.cookies.token === "" || !req.cookies.token) {
        return res.redirect("/login");
    }
    try {
        let data = jwt.verify(req.cookies.token, "shhh");
        req.user = data;
        next();
    } catch (error) {
        console.error("JWT verification failed:", error);
        return res.redirect("/login");
    }
}

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});