const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function (app) {
  // Proxy React dev requests to local Netlify Functions server
  // /api/* -> http://localhost:9999/.netlify/functions/api/*
  app.use(
    '/api',
    createProxyMiddleware({
      target: 'http://localhost:9999',
      changeOrigin: true,
      pathRewrite: {
        '^/api': '/.netlify/functions/api',
      },
      logLevel: 'warn',
      secure: false,
    })
  );
};