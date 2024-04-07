const express = require('express');
const app = express();
const path = require('path');
const mysql = require('mysql');
const session = require('express-session');
const bcrypt = require('bcrypt');
const moment = require('moment');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: '2345klij@#q4-_tgni34qufyb2347%b78wc342nfu23849^*2893cd*',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));
app.use((req, res, next) => {
    res.locals.loggedIn = req.session.loggedIn || false;
    next();
});
const pool = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'abc123',
  database: 'mcdse115'
});
pool.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('Connected to the MySQL Server!');
});
function checkAuth(req, res, next) {
    if (req.session.userId) {
      req.session.loggedIn = true;
      next();
    } else {
      req.session.loggedIn = false;
      res.redirect('/login');
    }
}
app.set('view engine', 'ejs');
app.use(express.static('public'));

app.get('/', (req, res) => res.render('landing'));
app.get('/navbar', (req, res) => res.render('navbar'));
app.get('/workspaces', (req, res) => res.render('workspaces'));
app.get('/register', (req, res) => res.render('register'));
app.post('/register', (req, res) => {
    const { username, email, country, phone, password } = req.body;
    if (password.length < 6 || username.length < 6) {
        return res.render('register', { errorMsg: 'Username and password must be at least 6 characters long.' });
    }
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Server error');
      }
      pool.query('INSERT INTO users (username, email, password, phone, country) VALUES (?, ?, ?, ?, ?)', [username, email, hash, phone, country], (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Database error');
        }
        res.redirect('/login');
      });
    });
});
app.get('/login', (req, res) => {
    const errorMsg = req.query.errorMsg;
    const loggedIn = req.session.loggedIn || false;
    res.render('login', { errorMsg: errorMsg, loggedIn: loggedIn });  
});
app.post('/login', (req, res) => {
    const { usernameOrEmail, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ? OR email = ?';
    pool.query(query, [usernameOrEmail, usernameOrEmail], async (err, users) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        if (users.length === 0) {
            return res.render('login', { errorMsg: 'Invalid username/email or password.' });
        }
        const user = users[0];
        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                req.session.userId = user.id;
                req.session.loggedIn = true;

                req.session.save(err => {
                    if (err) {
                        console.error(err);
                        return res.status(500).send('Error saving session');
                    }
                    res.redirect('/');
                });
            } else {
                res.render('login', { errorMsg: 'Invalid username/email or password.' });
            }
        } catch (compareError) {
            console.error(compareError);
            res.status(500).send('Error while comparing passwords');
        }
    });
});
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});
app.get('/get-states', (req, res) => {
    const country = req.query.country;
    pool.query('SELECT DISTINCT state FROM workspace WHERE country = ?', [country], (err, results) => {
        if (err) {
            return res.status(500).send('Error fetching states');
        }
        res.json(results);
    });
});
app.get('/get-places', (req, res) => {
    const { country, state, solution } = req.query;
    let query = 'SELECT DISTINCT placename FROM workspace WHERE country = ? AND state = ? AND solution = ?';
    let queryParams = [country, state, solution];
    
    pool.query(query, queryParams, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        const places = results.map(row => ({ placename: row.placename }));
        res.json(places);
    });
});
app.get('/get-filtered-places', (req, res) => {
    const { country, state, solution } = req.query;
    let query = 'SELECT DISTINCT placename FROM workspace WHERE country = ? AND state = ? AND solution = ?';
    let queryParams = [country, state, solution];
    
    pool.query(query, queryParams, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        const places = results.map(row => ({ placename: row.placename }));
        res.json(places);
    });
});
app.get('/get-booking-options', (req, res) => {
    const { country, state, placename } = req.query;

    const query = 'SELECT ablehourly, pricehourly, abledaily, pricedaily, ablemonthly, pricemonthly, ableyearly, priceyearly FROM workspace WHERE country = ? AND state = ? AND placename = ? LIMIT 1';
    pool.query(query, [country, state, placename], (err, results) => {
        console.log(results)
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ error: 'Place not found' });
        }
    });
});
app.get('/booking', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const currentDate = new Date().toISOString().split('T')[0];
    
    // Fetch workspace data
    const workspaceSql = `
        SELECT * 
        FROM workspace
    `;
    pool.query(workspaceSql, [userId], (err, workspace) => {
        if (err) {
            console.error('Error fetching workspace data:', err);
            return res.status(500).send('Error fetching workspace data');
        }

        res.render('booking', { workspace: workspace });
    });
});
app.post('/booking', checkAuth, (req, res) => {
    const { fullname, email, phone, solution, country, state, placename, capacity, startdate, enddate, startTime, endTime, hourlydate, totalPrice } = req.body;
    const userId = req.session.userId;

    const formattedStartDate = startdate ? new Date(startdate).toISOString().slice(0, 10) : null;
    const formattedEndDate = enddate ? new Date(enddate).toISOString().slice(0, 10) : null;
    const formattedBookDate = new Date().toISOString().slice(0, 10); // Today's date for bookdate
    const formattedStartTime = startTime ? new Date(`1970-01-01T${startTime}`).toISOString().slice(11, 19) : null;
    const formattedEndTime = endTime ? new Date(`1970-01-01T${endTime}`).toISOString().slice(11, 19) : null;
    const formattedHourlyDate = hourlydate ? new Date(hourlydate).toISOString().slice(0, 10) : null;

    pool.query('SELECT username FROM users WHERE id = ?', [userId], (err, userResult) => {
        if (err) {
            console.error('Error retrieving username:', err);
            return res.status(500).send('Error retrieving username');
        }
        const username = userResult[0].username;

        const insertQuery = `
            INSERT INTO booking (
                username, fullname, email, phone, capacity, startdate, enddate, bookdate, 
                country, state, places, solution, totalprice, starttime, endtime, hourlydate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            username, fullname, email, phone, capacity, formattedStartDate, formattedEndDate, formattedBookDate, 
            country, state, placename, solution, totalPrice, formattedStartTime, formattedEndTime, formattedHourlyDate
        ];
      
        pool.query(insertQuery, values, (insertErr, result) => {
            if (insertErr) {
                console.error('Error saving booking:', insertErr);
                return res.status(500).send('Error saving booking');
            }
            console.log('Booking saved successfully:', result);
            res.redirect('/book');
        });
    });
});
app.get('/book', checkAuth, (req, res) => {
    const userId = req.session.userId;
    const currentDate = new Date().toISOString().split('T')[0];

    const upcomingSql = `
        SELECT booking.*
        FROM booking
        INNER JOIN users ON booking.username = users.username
        WHERE users.id = ? AND (booking.cancel = '' OR booking.cancel IS NULL)
        AND ((booking.startdate >= ?) OR (booking.hourlydate >= ?))
    `;
    pool.query(upcomingSql, [userId, currentDate, currentDate], (err, upcomingBookings) => {
        if (err) {
            console.error('Error fetching upcoming bookings:', err);
            return res.status(500).send('Error fetching upcoming bookings');
        }
        
        const canceledSql = `
            SELECT booking.*
            FROM booking
            INNER JOIN users ON booking.username = users.username
            WHERE users.id = ? AND booking.cancel = 'yes'
        `;
        pool.query(canceledSql, [userId], (err, canceledBookings) => {
            if (err) {
                console.error('Error fetching canceled bookings:', err);
                return res.status(500).send('Error fetching canceled bookings');
            }

            const passedSql = `
                SELECT booking.*
                FROM booking
                INNER JOIN users ON booking.username = users.username
                WHERE users.id = ? AND (booking.cancel = '' OR booking.cancel IS NULL)
                AND (DATE(booking.enddate) <= ? OR DATE(booking.hourlydate) < ?)
            `;
            pool.query(passedSql, [userId, currentDate, currentDate], (err, passedBookings) => {
                if (err) {
                    console.error('Error fetching passed bookings:', err);
                    return res.status(500).send('Error fetching passed bookings');
                }

                res.render('book', {
                    upcomingBookings: upcomingBookings,
                    canceledBookings: canceledBookings,
                    passedBookings: passedBookings
                });
            });
        });
    });
});
app.post('/cancel-booking', checkAuth, (req, res) => {
    const bookingId = req.body.bookingId;
    // Update the cancel column in the database for the specified bookingId
    const sql = 'UPDATE booking SET cancel = ? WHERE id = ?';
    pool.query(sql, ['yes', bookingId], (err, result) => {
        if (err) {
            console.error('Error cancelling booking:', err);
            return res.status(500).send('Error cancelling booking');
        }
        res.sendStatus(200);
    });
});
app.get('/profile', checkAuth, (req, res) => {
    const userId = req.session.userId;
    pool.query('SELECT username, email, phone ,password FROM users WHERE id = ?', [userId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        if (result.length === 0) {
            return res.status(404).send('User not found');
        }
        const user = result[0];
        res.render('profile', { user: user });
    });
});
app.post('/change-password', checkAuth, async (req, res) => {
    const { oldPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.userId;
  
    if (newPassword !== confirmNewPassword) {
        return res.status(400).send("New passwords do not match.");
    }
  
    const query = 'SELECT password FROM users WHERE id = ?';
    pool.query(query, [userId], async (err, result) => {
        if (err) {
            return res.status(500).send("Database error.");
        }
        
        const user = result[0];
        
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).send("Old password is incorrect.");
        }
        
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        
        const updateQuery = 'UPDATE users SET password = ? WHERE id = ?';
        pool.query(updateQuery, [hashedNewPassword, userId], (updateErr, updateResult) => {
            if (updateErr) {
                // Handle update error
                req.session.message = {
                    type: 'error',
                    content: 'Failed to update password.'
                };
                return res.redirect('/profile');
            }
            
            // Set a success message in the session
            req.session.message = {
                type: 'success',
                content: 'Password successfully updated.'
            };

            // Redirect back to the profile page
            return res.redirect('/profile');
        });
    });
});
app.get('/review', (req, res) => {
    const currentDate = new Date().toISOString().split('T')[0];
    pool.query(`SELECT * FROM booking WHERE (cancel IS NULL OR cancel != ?) AND enddate <= ?`, ['yes', currentDate], (err, bookingResults) => {
        if (err) {
            console.error('Error fetching bookings:', err);
            return res.status(500).send('Error fetching bookings');
        } 
        if (!Array.isArray(bookingResults)) {
            console.error('Invalid booking data:', bookingResults);
            return res.status(500).send('Invalid booking data');
        }
        res.render('review', { bookings: bookingResults });
    });
});
app.post('/submit-review', (req, res) => {
    const { bookingId, rating, comment } = req.body;
    const username = req.session.username;

    const sql = 'INSERT INTO reviews (username, bookid, rating, comment) VALUES (?, ?, ?, ?)';
    const values = [username, bookingId, rating, comment];
    pool.query(sql, values, (err, result) => {
        if (err) {
            console.error('Error submitting review:', err);
            res.status(500).send('Error submitting review');
        } else {
            res.redirect('/review');
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
