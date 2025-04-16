import express, { Express } from 'express';
import morgan from 'morgan';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import config from './config';
import { configureSecurityMiddleware } from './middlewares/security.middleware';
import { errorHandler, notFoundHandler } from './middlewares/error.middleware';
import authRoutes from './routes/auth.routes';

const app: Express = express();

// Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cookie parser
app.use(cookieParser());

// Logging
if (config.env !== 'test') {
  app.use(morgan(config.env === 'development' ? 'dev' : 'combined'));
}

// Compression
app.use(compression());

// Security middleware (helmet, cors, rate limiting)
configureSecurityMiddleware(app);

// API routes
app.use(`${config.apiPrefix}/auth`, authRoutes);

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'sk8-auth-service',
    version: process.env.npm_package_version || '1.0.0',
  });
});

// Not found handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// Start the server
const PORT = config.port;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err);
  server.close(() => {
    process.exit(1);
  });
});

// Handle SIGTERM signal
process.on('SIGTERM', () => {
  console.log('SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('Process terminated!');
  });
});

export default app; 