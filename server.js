const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const flash = require('express-flash');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

// Timezone helper functions (matching admin portal)
function formatTimeWithTimezone(dateTime, timezone) {
    if (!dateTime) return null;

    const date = new Date(dateTime);
    const timeString = date.toLocaleString("en-US", {
        timeZone: timezone || "America/New_York",
        hour: "numeric",
        minute: "2-digit",
        hour12: true
    });

    const tzAbbr = date.toLocaleString("en-US", {
        timeZone: timezone || "America/New_York",
        timeZoneName: "short"
    }).split(" ").pop();

    return `${timeString} ${tzAbbr}`;
}

function formatDateWithTimezone(dateTime, timezone) {
    if (!dateTime) return null;

    const date = new Date(dateTime);
    return date.toLocaleDateString("en-US", {
        timeZone: timezone || "America/New_York",
        month: "short",
        day: "numeric",
        year: "numeric"
    });
}

const app = express();
const PORT = process.env.PORT || 3003;

// Database connection (matching admin portal exactly)
const db = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "dojoapp",
    password: process.env.DB_PASSWORD || "djppass",
    database: process.env.DB_NAME || "dojopro",
    timezone: '+00:00'
});

// Test database connection
db.connect((err) => {
    if (err) {
        console.error('Member Portal: Database connection failed:', err);
    } else {
        console.log('Member Portal: Connected to MariaDB database');
    }
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());

// Session configuration (matching admin portal)
app.use(session({
    secret: process.env.SESSION_SECRET || 'dojopro-member-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

app.use(flash());

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Global middleware to pass user session and club data to all templates
app.use(async (req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.messages = req.flash();
    res.locals.formatTimeWithTimezone = formatTimeWithTimezone;
    res.locals.formatDateWithTimezone = formatDateWithTimezone;
    
    try {
        // Extract club from subdomain or parameter
        const host = req.get('host') || '';
        let subdomain = 'demo';
        
        if (host.includes('.')) {
            subdomain = host.split('.')[0];
        }
        
        // Allow override with query parameter for development
        subdomain = req.query.club || subdomain;
        
        // Load club data from database
        const query = `
            SELECT c.*, cs.logo_url, cs.primary_color, cs.secondary_color, cs.timezone
            FROM clubs c 
            LEFT JOIN club_settings cs ON c.club_id = cs.club_id 
            WHERE c.subdomain = ? AND c.status = 'active'
        `;
        
        db.query(query, [subdomain], (err, results) => {
            if (err) {
                console.error('Error loading club data:', err);
                res.locals.club = { name: 'DojoPro', club_id: 1, subdomain: 'demo' };
            } else if (results.length > 0) {
                res.locals.club = results[0];
            } else {
                // Default demo club
                res.locals.club = {
                    club_id: 1,
                    name: 'Demo Martial Arts Club',
                    subdomain: subdomain,
                    logo_url: null,
                    primary_color: '#667eea',
                    secondary_color: '#764ba2',
                    timezone: 'America/New_York'
                };
            }
            next();
        });
    } catch (error) {
        console.error('Middleware error:', error);
        res.locals.club = { name: 'DojoPro', club_id: 1, subdomain: 'demo' };
        next();
    }
});

// Authentication middleware
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/auth/login');
    }
    next();
}

// Routes

// Home page - redirect based on authentication
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.render('index', { 
            title: 'Member Portal',
            currentPage: 'home'
        });
    }
});

// Login page
app.get('/auth/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('auth/login', {
        title: 'Member Login',
        currentPage: 'login'
    });
});

/*
// Login processing (matching admin portal patterns)
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const club_id = res.locals.club.club_id;

        if (!email || !password) {
            req.flash('error', 'Please provide both email and password');
            return res.redirect('/auth/login');
        }

        // Find member with user account
        const query = `
            SELECT m.*, u.password_hash, u.user_id
            FROM members m 
            LEFT JOIN member_accounts ma ON m.member_id = ma.member_id
            LEFT JOIN users u ON ma.user_id = u.user_id
            WHERE m.email = ? AND m.club_id = ? AND m.status = 'active' AND m.deleted_at IS NULL
        `;

        db.query(query, [email, club_id], async (err, results) => {
            if (err) {
                console.error('Login query error:', err);
                req.flash('error', 'An error occurred. Please try again.');
                return res.redirect('/auth/login');
            }

            if (results.length === 0) {
                req.flash('error', 'Invalid email or password');
                return res.redirect('/auth/login');
            }

            const member = results[0];

            if (!member.password_hash) {
                req.flash('error', 'Your account is not set up for online access. Please contact the club.');
                return res.redirect('/auth/login');
            }

            const validPassword = await bcrypt.compare(password, member.password_hash);
            if (!validPassword) {
                req.flash('error', 'Invalid email or password');
                return res.redirect('/auth/login');
            }

            // Create session
            req.session.user = {
                user_id: member.user_id,
                member_id: member.member_id,
                club_id: member.club_id,
                first_name: member.first_name,
                last_name: member.last_name,
                email: member.email,
                belt_rank: member.belt_rank,
                membership_type: member.membership_type,
                household_id: member.household_id,
                is_primary_member: member.is_primary_member
            };

            req.flash('success', `Welcome back, ${member.first_name}!`);
            res.redirect('/dashboard');
        });

    } catch (error) {
        console.error('Login error:', error);
        req.flash('error', 'An error occurred. Please try again.');
        res.redirect('/auth/login');
    }
});


*/


// added by claude.
// Enhanced login with detailed debugging
app.post('/auth/login', async (req, res) => {
    try {
        let email = req.body.email;
        let password = req.body.password;
        
        // Handle arrays (our previous fix)
        if (Array.isArray(email)) email = email[0];
        if (Array.isArray(password)) password = password[0];

        const club_id = res.locals.club.club_id;

        console.log('🔍 Login attempt:', { email, password: password ? '***provided***' : 'NO PASSWORD', club_id });

        if (!email) {
            console.log('❌ No email provided');
            req.flash('error', 'Please provide your email address');
            return res.redirect('/auth/login');
        }

        // Find member
        const memberQuery = 'SELECT * FROM members WHERE email = ? AND club_id = ? AND status = ?';
        
        console.log('🔍 Looking for member with query:', memberQuery);
        console.log('🔍 Query params:', [email, club_id, 'active']);
        
        db.query(memberQuery, [email, club_id, 'active'], (err, memberResults) => {
            if (err) {
                console.error('❌ Member query error:', err);
                req.flash('error', 'Database error occurred');
                return res.redirect('/auth/login');
            }

            console.log('📊 Member query results:', memberResults.length, 'members found');
            
            if (memberResults.length === 0) {
                console.log('❌ No member found for:', email, 'in club:', club_id);
                req.flash('error', 'No member found with that email in this club');
                return res.redirect('/auth/login');
            }

            const member = memberResults[0];
            console.log('✅ Found member:', member.first_name, member.last_name, 'ID:', member.member_id);

            // Check if member has user account
            const userQuery = 'SELECT u.password_hash, u.user_id FROM member_accounts ma JOIN users u ON ma.user_id = u.user_id WHERE ma.member_id = ?';

            console.log('🔍 Looking for user account for member:', member.member_id);

            db.query(userQuery, [member.member_id], async (err, userResults) => {
                if (err) {
                    console.error('❌ User query error:', err);
                    req.flash('error', 'Database error occurred');
                    return res.redirect('/auth/login');
                }

                console.log('📊 User query results:', userResults.length, 'user accounts found');

                // NO USER ACCOUNT - Create one and redirect to password setup
                if (userResults.length === 0) {
                    console.log('🔧 No user account found, creating one for member:', member.member_id);
                    
                    // Create user account without password
                    const createUserQuery = 'INSERT INTO users (email, first_name, last_name, password_hash) VALUES (?, ?, ?, ?)';
                    
                    db.query(createUserQuery, [member.email, member.first_name, member.last_name, ''], (err, userInsert) => {
                        if (err) {
                            console.error('❌ User creation error:', err);
                            req.flash('error', 'Unable to create user account');
                            return res.redirect('/auth/login');
                        }

                        const newUserId = userInsert.insertId;
                        console.log('✅ Created user account with ID:', newUserId);

                        // Link member to user account
                        const linkQuery = 'INSERT INTO member_accounts (member_id, user_id) VALUES (?, ?)';
                        
                        db.query(linkQuery, [member.member_id, newUserId], (err) => {
                            if (err) {
                                console.error('❌ Member account link error:', err);
                                req.flash('error', 'Unable to link accounts');
                                return res.redirect('/auth/login');
                            }

                            console.log('✅ Linked member', member.member_id, 'to user', newUserId);

                            // Store member info in session for password setup
                            req.session.passwordSetup = {
                                user_id: newUserId,
                                member_id: member.member_id,
                                club_id: member.club_id,
                                first_name: member.first_name,
                                last_name: member.last_name,
                                email: member.email
                            };

                            console.log('🔄 Redirecting to password setup for:', member.first_name);
                            req.flash('info', `Welcome ${member.first_name}! Please set up your password to continue.`);
                            res.redirect('/auth/setup-password');
                        });
                    });

                    return; // Exit here for new account creation
                }

                const userAccount = userResults[0];
                console.log('✅ Found user account:', userAccount.user_id, 'Password exists:', !!userAccount.password_hash);

                // USER ACCOUNT EXISTS BUT NO PASSWORD - Redirect to password setup
                if (!userAccount.password_hash || userAccount.password_hash === '') {
                    console.log('🔧 User account exists but no password set, redirecting to setup');
                    
                    req.session.passwordSetup = {
                        user_id: userAccount.user_id,
                        member_id: member.member_id,
                        club_id: member.club_id,
                        first_name: member.first_name,
                        last_name: member.last_name,
                        email: member.email
                    };

                    req.flash('info', `Welcome back ${member.first_name}! Please set up your password to continue.`);
                    res.redirect('/auth/setup-password');
                    return;
                }

                // NORMAL LOGIN FLOW - Password provided and exists
                if (!password) {
                    console.log('❌ Password required but not provided');
                    req.flash('error', 'Please provide your password');
                    return res.redirect('/auth/login');
                }

                // Rest of normal login code...
                console.log('🔐 Proceeding with normal password validation');
                // ... (rest of your existing login code)
            });
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        req.flash('error', 'An error occurred. Please try again.');
        res.redirect('/auth/login');
    }
});



// Password setup page
app.get('/auth/setup-password', (req, res) => {
    if (!req.session.passwordSetup) {
        req.flash('error', 'Invalid password setup session');
        return res.redirect('/auth/login');
    }

    res.render('auth/setup-password', {
        title: 'Set Up Password',
        currentPage: 'setup',
        member: req.session.passwordSetup
    });
});

// Password setup processing
app.post('/auth/setup-password', async (req, res) => {
    try {
        if (!req.session.passwordSetup) {
            req.flash('error', 'Invalid password setup session');
            return res.redirect('/auth/login');
        }

        let { password, confirmPassword } = req.body;
        
        // Handle arrays
        if (Array.isArray(password)) password = password[0];
        if (Array.isArray(confirmPassword)) confirmPassword = confirmPassword[0];

        if (!password || !confirmPassword) {
            req.flash('error', 'Please provide both password fields');
            return res.redirect('/auth/setup-password');
        }

        if (password !== confirmPassword) {
            req.flash('error', 'Passwords do not match');
            return res.redirect('/auth/setup-password');
        }

        if (password.length < 6) {
            req.flash('error', 'Password must be at least 6 characters long');
            return res.redirect('/auth/setup-password');
        }

        const member = req.session.passwordSetup;
        
        // Hash the password
        const passwordHash = await bcrypt.hash(password, 10);
        
        // Update user account with password
        const updateQuery = 'UPDATE users SET password_hash = ? WHERE user_id = ?';
        
        db.query(updateQuery, [passwordHash, member.user_id], (err) => {
            if (err) {
                console.error('❌ Password update error:', err);
                req.flash('error', 'Unable to set password');
                return res.redirect('/auth/setup-password');
            }

            console.log('✅ Password set for user:', member.user_id);

            // Clear password setup session
            delete req.session.passwordSetup;

            // Create normal user session
            req.session.user = {
                user_id: member.user_id,
                member_id: member.member_id,
                club_id: member.club_id,
                first_name: member.first_name,
                last_name: member.last_name,
                email: member.email,
                belt_rank: null, // Will be loaded from member record
                membership_type: null,
                household_id: null,
                is_primary_member: 0
            };

            req.flash('success', `Welcome to the member portal, ${member.first_name}! Your password has been set.`);
            res.redirect('/dashboard');
        });

    } catch (error) {
        console.error('❌ Password setup error:', error);
        req.flash('error', 'An error occurred while setting up your password');
        res.redirect('/auth/setup-password');
    }
});






// Dashboard (protected route)
app.get('/dashboard', requireAuth, (req, res) => {
    const member = req.session.user;
    const club = res.locals.club;

    // Get member stats
    const statsQuery = `
        SELECT 
            COUNT(*) as total_visits,
            COUNT(CASE WHEN ci.check_in_time >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) as visits_this_month,
            MAX(ci.check_in_time) as last_visit
        FROM check_ins ci 
        WHERE ci.member_id = ?
    `;

    // Get recent check-ins
    const checkinsQuery = `
        SELECT ci.*, l.location_name, l.timezone as location_timezone
        FROM check_ins ci
        JOIN locations l ON ci.location_id = l.location_id
        WHERE ci.member_id = ? 
        ORDER BY ci.check_in_time DESC 
        LIMIT 10
    `;

    // Check current check-in status
    const currentCheckinQuery = `
        SELECT ci.*, l.location_name 
        FROM check_ins ci
        JOIN locations l ON ci.location_id = l.location_id
        WHERE ci.member_id = ? AND ci.check_out_time IS NULL
        ORDER BY ci.check_in_time DESC LIMIT 1
    `;

    db.query(statsQuery, [member.member_id], (err, statsResults) => {
        if (err) {
            console.error('Stats query error:', err);
            return res.render('error', { title: 'Dashboard Error', error: { message: 'Unable to load dashboard' } });
        }

        const stats = statsResults[0] || { total_visits: 0, visits_this_month: 0, last_visit: null };

        db.query(checkinsQuery, [member.member_id], (err, checkinResults) => {
            if (err) {
                console.error('Check-ins query error:', err);
                return res.render('error', { title: 'Dashboard Error', error: { message: 'Unable to load dashboard' } });
            }

            db.query(currentCheckinQuery, [member.member_id], (err, currentResults) => {
                if (err) {
                    console.error('Current check-in query error:', err);
                    return res.render('error', { title: 'Dashboard Error', error: { message: 'Unable to load dashboard' } });
                }

                res.render('dashboard/index', {
                    title: 'Member Dashboard',
                    currentPage: 'dashboard',
                    member,
                    stats,
                    checkins: checkinResults,
                    currentCheckin: currentResults[0] || null
                });
            });
        });
    });
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'member-portal',
        timestamp: new Date().toISOString(),
        database: db.state === 'authenticated' ? 'connected' : 'disconnected'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('error', {
        title: 'Page Not Found',
        currentPage: 'error',
        error: {
            status: 404,
            message: 'The page you are looking for does not exist.'
        }
    });
});

app.listen(PORT, () => {
    console.log(`DojoPro Member Portal running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});