require('dotenv').config()
let router = require('express').Router()
let db = require('../models')
let jwt = require('jsonwebtoken')

// POST /auth/login (find and validate user; send token)
router.post('/login', (req, res) => {
  console.log(req.body)
  // look up user
  db.User.findOne({email: req.body.email})
  .then(user => {
    // make sure user exists and has a password
    if (!user || !user.password) {
      return res.status(404).send({message: 'User not found'})
    }
    //good, now chec password
    if (!user.isValidPassword(req.body.password)) {
      return res.status(401).send({message: 'password is incorrect'})
    }

    // good user - issue token
    let token = jwt.sign(user.toJSON(), process.env.JWT_SECRET, {
      expiresIn: 60 //in seconds
    })
    res.send({token})
})
  .catch(err =>{
    console.log('error in POST/auth/login', err)
    res.status(503).send({message: 'database or server-side error'})
  })

})

// POST to /auth/signup (create user; generate token)
router.post('/signup', (req, res) => {
  console.log(req.body)
  //look up user and make sure not a duplicate
  db.User.findOne({email: req.body.email})
    .then(user =>{
      //if the user exists, do NOT let them create another account
      if (user) {
        // bad - this is signup, they shouldn't already exist
        return res.status(409).send({message: 'Email address in use'})
      }
        // good - user does not exist
      db.User.create(req.body)
        .then(newUser => {
          // have new user, now need to make them a token
          let token = jwt.sign(newUser.toJSON(), process.env.JWT_SECRET, {
            expiresIn: 60 //60*60*8 //8 hours in seconds
          })
          // then send token to caller
          res.send({ token })
          })
        .catch(err => {
         console.log('Error in creating user', err)
          res.status(500).send({message: 'Error creating user'})
        })
      })
    .catch(err => {
      console.log('Error in POST/AUTH signup', err)
      res.status(503).send({message: 'Database or server error'})
  })
})

// NOTE: User should be logged in to access this route
router.get('/profile', (req, res) => {
  // The user is logged in, so req.user should have data!
  // TODO: Anything you want here!

  // NOTE: This is the user data from the time the token was issued
  // WARNING: If you update the user info those changes will not be reflected here
  // To avoid this, reissue a token when you update user data
  res.send({ message: 'Secret message for logged in people ONLY!' })
})

module.exports = router
