const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('../models/user');

// serializar los datos; o gaurdarlo en un archivo del navegador mediante passport
passport.serializeUser((user, done)=>{
    done( null, user.id );
});

// consulta a DB para ver si existe 
passport.deserializeUser(async( id, done)=>{
    const user = await User.findById(id);
    done( null, user);
});

// para registrar usuario↓↓
passport.use('local-signup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
},async(req, email, password, done)=>{     

    const user = await User.findOne({email: email});
    //revisa la existencia del usuario 
    if(user){
        return done(null, false, req.flash('signupMessage','The eemail is already taken.'));
    }else{
        const newUser = new User();
        newUser.email = email; 
        newUser.password = newUser.encryptPassword(password);
        await newUser.save();
        done( null, newUser);
    }
   
}));

// ocmprobacion si el usuario existe o no
passport.use('local-signin', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
},async(req, email,password,done)=>{
    // consulta a BD↓↓
    const user = await User.findOne({email:email});
    if(!user){
        // (null, falso para el usuario xq no existe tu usuario, flash.. )
        return done( null, false, req.flash('signinMessage','No user foundd.'));
    }
    if(!user.comparePassword(password)){
        return done(null, false, req.flash('signinMessage','Incorrect Password'));
    }
    return done(null, user); 
}));