const express = require('express');
// metodo Router devuelve un objeto le puede poner el nombre que quieras 
const router = express.Router(); 
const passport = require('passport');

router.get('/', ( req, res, next) => {
  res.render('index');
});

router.get('/signup', ( req, res, next) => {
    res.render('signup');
});

// router.post('/signup', ( req, res, next) => {
//     console.log(req.body);
//     res.send('resived');    
// });

//registra
router.post('/signup', passport.authenticate('local-signup',{
    successRedirect: '/profile',
    failureRedirect: '/signup',
    passReqToCallback: true
}));

router.get('/signin', ( req, res, next) => {
    res.render('signin');
}); 

router.post('/signin', passport.authenticate('local-signin',{
    successRedirect: '/profile',
    failureRedirect: '/signin',
    passReqToCallback: true
}));

router.get('/logout', (req, res, next)=>{
    req.logout();
    res.redirect('/');
});

router.use((req,res,next)=>{
    isAuthenticated(req, res, next);
    next();  
});

router.get('/profile',isAuthenticated, (req,res,next)=>{
    res.render('profile');
});

// router.get('/dashboard',(req,res,next)=>{
//    res.send('dashboard');
// });

function isAuthenticated( req, res, next ) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect('/');
};

module.exports = router;