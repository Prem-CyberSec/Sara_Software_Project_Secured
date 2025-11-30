require('dotenv').config();
const express = require('express');
const app = express();
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const fileUpload = require('express-fileupload');
const rateLimit = require('express-rate-limit')
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    error: 'Too many authentication attempts. Please try again later.'
  },
  standardHeaders: true,  // Return rate limit info in the RateLimit-* headers
  legacyHeaders: false,
});
const logger = require('../config/logger');
const stream = {
  write: (message) => logger.info(message.trim()),
}
const allowedOrigins = ['http://localhost:3000']; // adjust with your frontend domains
const cookieParser = require('cookie-parser')

//Middleware
app.use(cookieParser());
app.use(express.json());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  dnsPrefetchControl: {allow: false},
  frameguard: {action: 'deny'},
  hidePoweredBy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  permittedCrossDomainPolicies: 'none',
  referrerPolicy: { policy: 'strict-origin-when-cross-origin'},
  xssFilter: true  
}));
app.use('/api/auth/', authLimiter);
app.use(cors({
  origin: function(origin, callback){
    if(!origin) return callback(null, true); //Alow server-to-server or Postman calls with no origin
    if(allowedOrigins.indexOf(origin) === -1){
      const msg = `The CORS policy for this site does not allow access from the specified origin: ${origin}`;
      return callback(null, true);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT','DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.use(morgan('combined', {stream}));
app.use(fileUpload({
  createParentPath: true,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
}));

function ensureSecure(req, res, next) {
  if (res.secure || req.headers['x-forwarded-prot'] === 'https') {
    return next();
  }
  res.redirect(301, `https://${req.headers.host}${req.url}`);
}

if (process.env.NODE_ENV === 'production') {
  app.use(ensureSecure);
}

app.use((err, req, res, next) => {
  // Log full error stack internally
  logger.error('Unhandled error occurred', {
    message: err.message || err,
    stack: err.stack || '',
    method: req.method,
    url: req.originalUrl,
    userId: req.user ? req.user.id : undefined,
  });
  let clientMessage = err.clientMessage || err.message || 'Internal server error. Please contact support if the problem persists.';
  try {
  clientMessage = JSON.parse(clientMessage);
  } catch (e) {
  // Not a JSON string, send as is
  }
  res.status(err.status || 500).json({
    error: clientMessage
  });
});

//Routes
const authRoutes = require('./routes/auth');
const documentRoutes = require('./routes/documents');
const { error } = require('winston');
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);

// Global validation error handler
app.use((err, req, res, next) =>{
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err){
    logger.warn('Invalid JSON body', {
      url: req.originalUrl,
      method: req.method,
      userId: req.user?.id
    });
    return res.status(400).json({ error: 'Invalid JSON format' });
  }
  next(err);
});

//Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`SecureDocs API running on Port ${PORT}`)
})