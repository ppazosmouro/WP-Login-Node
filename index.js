let mysql   = require('mysql');
let express = require('express'), http = require('http'); 
let path = require('path');
let url = require("url");
let bodyParser  = require('body-parser');
let cookieParser = require('cookie-parser');
let md5 = require('md5');
'use strict';
let crypto = require('crypto');
//var Cookies = require('cookies')
// HASH
let hasher = require('wordpress-hash-node');
//------//
// Limiter login
const {RateLimiterMySQL} = require('rate-limiter-flexible');

//Serialize
phpjs = require('./serialize');

const PATH_APP = '/';
//DEFINE SALT WP
const AUTH_KEY = 'B>ma.i_YYY<A&e;WaJ0AIw$esaoNrvdy~Y[n{giHT9gB6rTI4hUC{CN3A4cH*&:u';
const SECURE_AUTH_KEY = 'G:Ax@s7Gtf~D6;QDH6<e7JM`hZ|y-G.c2r&s.B5-?%YxH4Z<R,7/L./^.[DxRdj&';
const LOGGED_IN_KEY = 'TLX,NUxHU%J^R*o:s(Kizbp$2_2g7I@,kJrtpOV8%E6ZSI*B_A`3n[%1]88|@QBA';
const AUTH_SALT = 'FV(P!h/VI93/^N9>(A8[;=_a7z& `ZquA>sA9F%U?ozWU:R1H_W!.!)%Fm@ s-7O';
const SECURE_AUTH_SALT = 'eA$8 by0&6=UqdvDTz-*k;|x/zgWrIx((rA/s([:kueAisQa<N(50c6{-_*ZPPdA';
const NONCE_KEY = 'w j{K+t0D;hx6qbSpePE7j: g5lzc6*%1.c90;hZ9EItaa>FD5>RWG,#8$eS{|jW';
const LOGGED_IN_SALT = 'm8G: j6OTS;Sdi4r^w?_kOCZqC8MwjI]K#TxUSy>X:Xe|?r%x-D&0j&1e{jjA|!m';
const NONCE_SALT = 'eyZ}eZ`1yEh].(B*q+8[K6@3T9D>x(-QBL%S,]}iQt&xXl?K[mo}6Q[EC|M%jLb#';

const DB_NAME = 'node_test';
const table_prefix = 'wp_';

const connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'root',
  password : '',
  database : DB_NAME,
});

const maxConsecutiveFailsByUsername = 5; //Limit login fails

const opts = {
  storeClient: connection,
  dbName: DB_NAME,
  tableName: table_prefix+'node_app_limiter_login', // all limiters store data in one table
  points: maxConsecutiveFailsByUsername, // Number of points
  duration: 60 * 5, // Store number for 5min since first fail
  blockDuration: 60 * 15, // Block for 15 minutes
};

const ready = (err) => {
  if (err) {
   	console.log(err); 
  } else {
    console.log('Limiter login runing...');
  }
};

const rateLimiter = new RateLimiterMySQL(opts, ready);

const SALT_KEY = LOGGED_IN_KEY + LOGGED_IN_SALT;
const ADMIN_SALT_KEY = AUTH_KEY + AUTH_SALT;
const ADMIN_SEC_KEY = SECURE_AUTH_KEY + SECURE_AUTH_SALT;

var LOGGED_IN_COOKIE = '';
var PLUGINS_COOKIE_PATH = '';
var COOKIE_DOMAIN = false;
var ADMIN_COOKIE_PATH = '';
var COOKIEPATH = '';
var SITECOOKIEPATH = '';
var COOKIEHASH = '';

var IS_SSL = false;
var secure_logged_in_cookie = false;


function wp_hash_log(string){
    var hmac = crypto.createHmac('md5', SALT_KEY);
    hmac.update(string); 
    return hmac.digest('hex'); 
};

function wp_hash_sec(string, secret){
    var hmac = crypto.createHmac('md5', secret);
    hmac.update(string); 
    return hmac.digest('hex'); 
};

function hash_hmac(string, key){
    var hmac = crypto.createHmac('sha256', key);
    hmac.update(string); 
    return hmac.digest('hex'); 
};

function get_token($length = 43){

    var randomChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var result = '';
    var length = $length;
    for ( var i = 0; i < length; i++ ) {
        result += randomChars.charAt(Math.floor(Math.random() * randomChars.length));
    }
    return result;
    //return crypto.randomBytes($length).toString('hex');
}


let app = express();

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(bodyParser.json());

var home = '';
var siteurl = '';

const algorithm = 'aes-256-ctr';
const secretKey = 'vOVH6sdmpNWjRRIqCc7rdxs01lwHzfr3';


// connection.query('SELECT * FROM '+table_prefix+'users', function(err, rows) {
//     if (err) { 
//         console.log("Database error: " + err);
//     } else {
//          for (var i = 0; i < rows.length; i++){
//             console.log("Rows[" + i + "] : " + rows[i].user_login + " " + rows[i].user_pass);
//          }
//     }
// });


connection.query('SELECT * FROM '+table_prefix+'options WHERE option_name = ? OR option_name = ?', ['siteurl', 'home'],function(err, rows, fields) {
    if (err) { 
        console.log("Database error: " + err);
    } else {


          for (const i in rows) {
            if(rows[i].option_name == 'home'){
              home = rows[i].option_value;
            }
            if(rows[i].option_name == 'siteurl'){
              siteurl = rows[i].option_value;
              console.log('siteurl: '+siteurl);
            }
            
          }

          if(siteurl != ''){

            IS_SSL = (url.parse(siteurl).protocol === 'https:')?true:false;
            secure_logged_in_cookie = IS_SSL;
            console.log('SSL: '+secure_logged_in_cookie);

            if( LOGGED_IN_COOKIE == '') {
              LOGGED_IN_COOKIE = 'wordpress_logged_in_'+md5(siteurl);
            }
            if(SITECOOKIEPATH == ''){
               SITECOOKIEPATH =  url.parse(siteurl+'/').pathname;
            }
            if(ADMIN_COOKIE_PATH == ''){
               ADMIN_COOKIE_PATH =  SITECOOKIEPATH+'wp-admin';
            }
            if(PLUGINS_COOKIE_PATH == ''){
               PLUGINS_COOKIE_PATH =  SITECOOKIEPATH+'wp-content/plugins' ;
            }
            if(COOKIEHASH == ''){
               COOKIEHASH =  md5(siteurl);
            }
          }

          if(home != ''){

            if(COOKIEPATH == ''){
               COOKIEPATH =  url.parse(home+'/').pathname ;
            }
          }
          
          

          console.log('cookie name: '+LOGGED_IN_COOKIE);
    }
});

app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname + '/login.html'));
});

async function loginRoute(req, res) {

  var username = req.body.username;
  var password = req.body.password;
  var statusBlockUser = await  rateLimiter.get(username);
  console.log(statusBlockUser);

  var activeBlokUser = true;
  if(statusBlockUser !== null && statusBlockUser.consumedPoints > maxConsecutiveFailsByUsername){
  		activeBlokUser = false;
  }
  console.log('status user: '+ activeBlokUser);

  if ( activeBlokUser ) {
	  if (username && password) {
	    connection.query('SELECT * FROM '+table_prefix+'users WHERE user_login = ?', [username], function(error, results, fields) {
	      if (results.length > 0) {
	        var pass_estored = results[0].user_pass;
	        //console.log('pw:'+ pass_estored);
	        if( hasher.CheckPassword(password, pass_estored) ){

	          const start = parseInt(Date.now()/1000);

	          var userID = results[0].ID;
	          var userLogin = results[0].user_login;
	          var pass_frag = pass_estored.substr( 8, 4 );
	          var expiration = start+(12 * 3600);

	          var auth_cookie_name = 'wordpress_'+COOKIEHASH;
	            var scheme;
	            var secret_aut = ADMIN_SALT_KEY;
	            if ( IS_SSL ) {
	                auth_cookie_name = 'wordpress_sec_'+COOKIEHASH;
	                scheme           = 'secure_auth';
	                secret_aut = ADMIN_SEC_KEY;
	              } else {
	                auth_cookie_name = 'wordpress_'+COOKIEHASH;
	                scheme           = 'auth';
	                secret_aut = ADMIN_SALT_KEY;
	            }

	          var token = get_token(43);

	          var hash_token = crypto.createHash('sha256').update(token).digest('hex');


	          var key = wp_hash_log( userLogin + '|' + pass_frag + '|' + expiration + '|' + token );
	          var hash = hash_hmac( userLogin + '|' + expiration + '|' + token, key );
	          var cookie = userLogin + '|' + expiration + '|' + token + '|' + hash;

	          var key_auth = wp_hash_sec( userLogin + '|' + pass_frag + '|' + expiration + '|' +  token, secret_aut);
	          var hash_auth = hash_hmac( userLogin + '|' + expiration + '|' + token, key_auth );
	          var cookie_auth = userLogin + '|' + expiration + '|' + token + '|' + hash_auth;
	    
	          
	          const UA = req.get('User-Agent');
	          const ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
	          var SESSION_TOKEN = {};

	          console.log('Token: '+token);
	          console.log('hash_token: '+hash_token);
	          SESSION_TOKEN[hash_token] = 
	            {
	              "expiration": expiration,
	              "ip": ip,
	              "ua": UA,
	              "login": start
	          };

	          var serializeSesionToken = phpjs.serialize(SESSION_TOKEN).replace(/(\'|\\)/g, '\\$1');


	          connection.query('SELECT * FROM '+table_prefix+'usermeta  WHERE meta_key = ? AND user_id = ?', ['session_tokens', userID], function(error, results, fields) {
	              if (results.length > 0) {

	                  connection.query('UPDATE '+table_prefix+'usermeta SET meta_value = ? WHERE meta_key = ? AND user_id = ?', [serializeSesionToken, 'session_tokens', userID], (error, results, fields) => {
	              
	                      if (error){
	                        return console.error(error.message);
	                      }
	                      console.log('Rows Update:', results.affectedRows);
	                  });

	              }else{

	                connection.query('INSERT INTO '+table_prefix+'usermeta ( user_id, meta_key, meta_value ) VALUES  ( ?, ?, ? )', [ userID, 'session_tokens', serializeSesionToken ], (error, results, fields) => {
	              
	                      if (error){
	                        return console.error(error.message);
	                      }
	                      console.log('Rows Insert:', results.affectedRows);
	                  });

	              }
	          });

	          	//current sessión APP
	          	res.cookie('cur_session', token, { expire: expiration });

	            //cookie = 'admin' + '|' + 1613861286 + '|' + '3zxSwjwgaprVlhTvF61fQQ9dad9Lic8Bmi56Av7ui2T' + '|' + 'b3d9279994d15e0bcf76add709fe5a948f388cb6c96661e61586800c4781c718';
	            res.cookie(LOGGED_IN_COOKIE, cookie, { expire: expiration, path: COOKIEPATH });

	            // Not work -- wp-admin cookie
	            res.cookie(auth_cookie_name, cookie_auth, { expire: expiration, path: PLUGINS_COOKIE_PATH });
	            res.cookie(auth_cookie_name, cookie_auth, { expire: expiration, path: ADMIN_COOKIE_PATH });
	            // end wp-admin cookie

	            res.cookie('wordpress_test_cookie', 'WP+Cookie+check', { path: COOKIEPATH });
	            res.cookie('wp-settings-time-'+userID, start, { path: COOKIEPATH });

	            //setcookie( LOGGED_IN_COOKIE, cookie, expiration, COOKIEPATH, COOKIE_DOMAIN, secure_logged_in_cookie, true );
	            //setcookie( $auth_cookie_name, $auth_cookie, $expire, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN, $secure, true );
	            //setcookie( $auth_cookie_name, $auth_cookie, $expire, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, $secure, true );
	            if ( COOKIEPATH != SITECOOKIEPATH ) {
	              res.cookie(LOGGED_IN_COOKIE, cookie, { expire: expiration, path: SITECOOKIEPATH });
	              //setcookie( LOGGED_IN_COOKIE, cookie, expiration, SITECOOKIEPATH, COOKIE_DOMAIN, secure_logged_in_cookie, true );
	            }
	            console.log('Run...');
	            // console.log('');
	            // console.log('key: '+key);
	            // console.log('Token: '+token);
	            // console.log('hash_hmac: '+hash);
	            // console.log('cookie: '+cookie);
	            
	            //console.log(serializeSesionToken);
	            //res.send('Login true!: '+userID);

	            rateLimiter.delete(username).then((rateLimiterRes) => {
				    console.log('Exist user limit_table: '+rateLimiterRes);
				  })
				  .catch((rej) => {
				    console.log('Error Delete');
				    console.log(rej);
				});

	            res.redirect(home);

	        }else{
	          //res.send('Incorrect Credentials!');
	            rateLimiter.consume(username)
				  .then((rateLimiterRes) => {
				    console.log('Failed attempts: '+rateLimiterRes.consumedPoints);
				  })
				  .catch((rej) => {
				    console.log('Error consume points:');
				    console.log(rej);
					});

	          res.redirect(PATH_APP+'?fail=1');
	        }
	      } else {

	      	rateLimiter.consume(username)
				  .then((rateLimiterRes) => {
				    console.log('Failed attempts: '+rateLimiterRes.consumedPoints);
				  })
				  .catch((rej) => {
				    console.log('Error consume points:');
				    console.log(rej);
				});

	        res.redirect(PATH_APP+'?fail=2');
	      }     
	      res.end();
	    });
	  } else {
	    // res.send('Please enter Username and Password!');
	    // res.end();
	    res.redirect(PATH_APP+'?fail=2');
	  }
	}else{
		res.redirect(PATH_APP+'?fail=3');
	}

}


app.get('/user-log-out', function(req, res) {

	var getToken = req.cookies.cur_session;
	if(getToken){
			var auth_cookie_name = 'wordpress_'+COOKIEHASH;
			var scheme;
			var secret_aut = ADMIN_SALT_KEY;
			if ( IS_SSL ) {
				auth_cookie_name = 'wordpress_sec_'+COOKIEHASH;
				scheme           = 'secure_auth';
				secret_aut = ADMIN_SEC_KEY;
			} else {
				auth_cookie_name = 'wordpress_'+COOKIEHASH;
				scheme           = 'auth';
				secret_aut = ADMIN_SALT_KEY;
			}
		  	res.clearCookie('foo');

		  	res.clearCookie(LOGGED_IN_COOKIE);

		  	res.clearCookie(auth_cookie_name);
		  	res.clearCookie(auth_cookie_name);
		  	// res.clearCookie('wp-settings-'+userID);
		  	// res.clearCookie('wp-settings-time-'+userID);

		  	if ( COOKIEPATH != SITECOOKIEPATH ) {
		  		res.clearCookie(LOGGED_IN_COOKIE);
		  	}

		  	res.clearCookie('cur_session');

		  	var hash_token = crypto.createHash('sha256').update(getToken).digest('hex');

		  	connection.query('DELETE FROM '+table_prefix+'usermeta WHERE meta_key = ? AND meta_value LIKE ?  ', ['session_tokens', '%'+hash_token+'%' ], (error, results, fields) => {
	              
	            if (error){
	                return console.error(error.message);
	            }

	            console.log('Rows Insert:', results.affectedRows);

	        });

			//res.send('Token: '+hash_token);
			res.redirect(PATH_APP);
	}
	else{
		res.redirect(PATH_APP);
	}

	res.end();
	
  
});

app.post('/auth', async function(req, res) {

  try {
		await loginRoute(req, res);
  }catch (err) {
  	console.log(err);
    res.status(500).end();
  }
  
});




// Crypto
/**
 * generates random string of characters i.e salt
 * @function
 * @param {number} length - Length of the random string.
 */
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};
/**
 * hash password with sha512.
 * @function
 * @param {string} password - List of required fields.
 * @param {string} salt - Data to be validated.
 */
var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
};
function saltHashPassword(userpassword) {
    //var salt = genRandomString(16); /** Gives us salt of length 16 */
    var salt = 'lm@U.ELJhEuliaisjgZ(B8yU3uv_rS;me.x2nE Dj6x$:yEmxVssQ@ici;Dd>1:_';
    var passwordData = sha512(userpassword, salt);
    console.log('UserPassword = '+userpassword);
    console.log('Passwordhash = '+passwordData.passwordHash);
    console.log('nSalt = '+passwordData.salt);
}

//saltHashPassword('12345');



app.listen(8000, () => {
  console.log('listening on port 8000');
});