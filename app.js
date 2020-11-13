var express = require('express');
var bodyParser = require('body-parser')
var session = require('express-session')
var cors = require('cors')
var striptags = require('striptags')
var hash = require('pbkdf2-password')()
var app = express();

app.use(session({
  resave: false, // don't save session if unmodified
  saveUninitialized: false, // don't create session until something stored
  secret: 'adopifjqeporihgepoih349ru834tgihej'
}));

var jsonBodyParser = bodyParser.json()
var urlEncodedBodyParser = bodyParser.urlencoded({extended: false})

// foo=bar&baz=norf&name=clark%20freifeld

app.use(jsonBodyParser)

// app.use(function(req, res, next) {
//   res.header("Access-Control-Allow-Origin", "http://localhost:4200");
//   res.header("Access-Control-Allow-Headers",
//       "Origin, X-Requested-With, Content-Type, Accept");
//   res.header("Access-Control-Allow-Methods",
//       "GET, POST, PUT, DELETE, OPTIONS");
//   res.header("Access-Control-Allow-Credentials", "true");
//   next();
// });
app.use(cors({
  origin: 'http://localhost:4200',
  credentials: true,
}))

function authenticate(name, pass, fn) {
  console.log('authenticating %s:%s', name, pass);
  var user = users.find(u => u.username === name) //users[name];
  console.log('got user: ', user)
  // query the db for the given username
  if (!user) {
    return fn(new Error('cannot find user'));
  }
  // apply the same algorithm to the POSTed password, applying
  // the hash against the pass / salt, if there is a match we
  // found the user
  hash({password: pass, salt: user.salt}, function (err, pass, salt, hash) {
    if (err) {
      return fn(err);
    }
    if (hash === user.hash) {
      console.log('successful login')
      return fn(null, user)
    }
    fn(new Error('invalid password'));
  });
}

let users = [
  {_id: '123', username: 'alice', password: 'alice'},
  {_id: '234', username: 'bob', password: 'bob'}
]

const findAllUsers = (req, res) => {
  res.json(users)
}

app.get('/api/users', findAllUsers);

const findUserById = (req, res) => {
  console.log(req.session)
  if (!req.session.user) {
    req.session.user = users.find(u => u._id === req.params.id)
  }
  res.json(req.session.user)
}

app.get('/api/users/:id', findUserById)

const createUser = (req, res) => {
  console.log(req.body)
  let newUser = req.body
  let username = striptags(req.body.username)
  if (username !== req.body.username) {
    res.json({status: 'Invalid username'})
    return
  }
  hash({password: newUser.password}, (err, pass, salt, hash) => {
    newUser._id = new Date().getTime();
    newUser.websites = newUser.websites.split(/,\s*/)
    newUser.hash = hash
    newUser.salt = salt
    users.push(newUser)
    let respUser = {...newUser}
    delete respUser.hash
    delete respUser.salt
    delete respUser.password
    res.json(respUser)
  });
}

app.post('/api/users', createUser);

const updateUser = (req, res) => {
  console.log(req.params.id)
  let user = users.find(u => u._id === req.params.id);
  user.username = req.body.username;
  user.password = req.body.password;
  res.json(user)
}

app.put('/api/users/:id', updateUser);

const deleteUser = (req, res) => {
  users = users.filter(u => u._id !== req.params.id)
  console.log(users)
  res.json(users)
}

app.delete('/api/users/:id', deleteUser)

app.post('/api/login', function (req, res) {
  authenticate(req.body.username, req.body.password, function (err, user) {
    if (err) {
      res.send({status: err})
    }
    console.log("auth succeeded, ", user)
    if (user) {
      // Regenerate session when signing in to prevent fixation
      req.session.regenerate(function () {
        // Store the user's primary key
        // in the session store to be retrieved,
        // or in this case the entire user object
        req.session.user = user;
        console.log("set user in session: ", req.session.user)
        req.session.success = 'Authenticated as ' + user.name
            + ' click to <a href="/logout">logout</a>. '
            + ' You may now access <a href="/restricted">/restricted</a>.';
        //res.redirect('back');
        res.json(user)
      });
    } else {
      req.session.error = 'Authentication failed, please check your '
          + ' username and password.';
      res.redirect('/login');
    }
  });
});

const restricted = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    req.session.error = 'Access denied!';
    res.json({status: "Not authenticated"})
  }
}

const getUserProfile = (req, res) => {
  let respUser = {...req.session.user}
  delete respUser.hash
  delete respUser.salt
  res.json(respUser)
}

app.get('/api/profile', restricted, getUserProfile)

app.get('/hello', function(req, res) {
  res.send('hello world');
});

app.listen(3000);
