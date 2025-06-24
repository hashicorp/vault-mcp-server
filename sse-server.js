import express from 'express';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';

import { createSession, deleteSession, getSession } from './session.js';

import { vaultPrompts, vaultResources, vaultTools } from './tools.js';
import { Vault } from './vault.js';

const app = express();
app.use(express.json());

const router = express.Router();

const PORT = process.env['PORT'] ?? 3000;
const POST_ENDPOINT = '/messages';

// Create our MCP Server
const mcpServer = new McpServer({
    name: 'MCP Server - Vault',
    version: '0.0.1',
});

// Load our vault tools
vaultTools.forEach((tool) => mcpServer.tool(...tool));

// Load our vault resources.
vaultResources.forEach((resource) => mcpServer.resource(...resource));

// Load our prompts
vaultPrompts.forEach((prompt) => mcpServer.prompt(...prompt));

// Create an express Connection Handler
const connectionHandler = async (req, res) => {
    console.log('connection request received');

    // TODO: Look at https://mcp-framework.com/docs/Transports/http-stream-transport vs https://mcp-framework.com/docs/Transports/sse/
    const transport = new SSEServerTransport(POST_ENDPOINT, res);

    console.log(`SSE created created with session id => ${transport.sessionId}`);

    let endpoint = req.query['VAULT_ADDR'] ?? 'http://127.0.0.1:8200';
    let token = req.headers['vault_token'] ?? req.query['VAULT_TOKEN'];

    if (!token) {
        return res.status(400).send({ messages: 'Bad token.' });
    }

    res.on('close', () => {
        console.log(`SSE connection closed for session => ${transport.sessionId}`);
        deleteSession(transport.sessionId);
    });

    let session = createSession(transport.sessionId);

    session.transport = transport;
    session.vault = new Vault(endpoint, token, null);

    await mcpServer.connect(transport);
};

// Message handler for processing SSE JSON RPC messages
const messageHandler = async (req, res) => {
    try {
        console.log('SSE message received: ', req.body);

        const sessionId = req.query.sessionId;

        if (!sessionId) {
            res.status(400).send({ messages: 'Bad session id.' });
            return;
        }
        const { transport } = getSession(sessionId);

        if (!transport) {
            res.status(400).send({
                messages: 'No transport found for sessionId.',
            });
            return;
        }

        await transport.handlePostMessage(req, res, req.body);
    } catch (err) {
        console.error(err);
    }
};

// This endpoint handles the JSON RPC messages
router.post(POST_ENDPOINT, messageHandler);

// This endpoint handles the initial SSE connection request
router.get('/sse', connectionHandler);

// Setup the router on the base path
app.use('/', router);

app.listen(PORT, () => {
    console.log(`MCP Streamable HTTP Server listening on port ${PORT}`);
});
