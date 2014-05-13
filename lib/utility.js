var request = require('request');
var bcrypt = require('bcrypt');
var db = require('../app/config');


exports.getUrlTitle = function(url, cb) {
  request(url, function(err, res, html) {
    if (err) {
      console.log('Error reading url heading: ', err);
      return cb(err);
    } else {
      var tag = /<title>(.*)<\/title>/;
      var match = html.match(tag);
      var title = match ? match[1] : url;
      return cb(err, title);
    }
  });
};

var rValidUrl = /^(?!mailto:)(?:(?:https?|ftp):\/\/)?(?:\S+(?::\S*)?@)?(?:(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))|localhost)(?::\d{2,5})?(?:\/[^\s]*)?$/i;

exports.isValidUrl = function(url) {
  return url.match(rValidUrl);
};

/************************************************************/
// Add additional utility functions below
/************************************************************/

exports.signUpUser = function(username, password, res, req){
  bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(password, salt, function(err, hash) {
      // Store hash in your password DB.
      db.knex('users').insert([{username: username, password: hash}])
      .then(function(a){
        exports.checkUser(username, password, function(err, exists){
          if (exists){
            req.session.regenerate(function(){
              req.session.user = username;
              res.redirect('/');
            });
          } else {
            // wasn't authenticated, back to sign up page
            res.render('signup');
          }
        });
      })
      .catch(function(err){
        if(err){
          console.log('Error inserting user, name probably already exists');
          // should be sending a message about the sign up fail with this
          res.render('signup');
        }
      });
    });
  });
};

exports.checkUser = function(username, password, callback){
  db.knex('users').where({
    username: username})
    .select('username', 'password')
    .then(function(a){
      if(!a[0].username){
        console.log('cant find user');
        return callback(new Error('cannot find user'));
      }
      if(a[0].username===username && bcrypt.compareSync(password, a[0].password)){
        console.log('passed');
        return callback(null, true);
      } else {
        console.log('sync aint working');
        return callback(new Error('invalid password'));
      }
    });
};
