const express = require('express')
const { createProxyMiddleware } = require('http-proxy-middleware')

const app = express();

const routes = {
    '/auth':'http://auth:3003',
    '/item':'http://item:3001',
    '/order':'http://order:3002'
}

// restream parsed body before proxying
var restream = function(proxyReq, req, res, options) {
    if (req.body) {
        let bodyData = JSON.stringify(req.body);
        // incase if content-type is application/x-www-form-urlencoded -> we need to change to application/json
        proxyReq.setHeader('Content-Type','application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        // stream the content
        proxyReq.write(bodyData);
    }
}

for(const route in routes){
    const target = routes[route];
    app.use(route, createProxyMiddleware({target, changeOrigin: true,onProxyReq: restream}));
}

const PORT = 8000;
app.listen(PORT, () => console.log("API GATEWAY STARTED"))
