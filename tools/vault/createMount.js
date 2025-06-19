import { z } from 'zod';
import { getSession } from '../../session.js';

export const toolCreateMount = [
    'create-mount',
    'Mount a secret engine type on a Vault Server at a given path.',
    {
        type: z.enum(['kv', 'kv2']).describe("The type of mount. Supported: 'kv' (KV v1), 'kv2' (KV v2)"),
        path: z.string().describe('The path where the mount will be created'),
        description: z.string().optional().describe('Optional description for the mount'),
        options: z.record(z.any()).optional().describe('Optional mount options'),
    },
    async ({ type, path, description, options }, { sessionId /*, authInfo*/ }) => {
        let { vault } = getSession(sessionId);

        try {
            path = path.replace(/^\/|\/$/g, '');

            let payload = { mount_point: path, type };

            if (payload.type === 'kv2') {
                payload.type = 'kv';
                payload.options = { ...(options ?? {}), version: '2' };
            }

            if (description) payload.description = description;

            await vault.mount(payload);

            return {
                content: [
                    {
                        type: 'text',
                        text: `Mount of type ${type} created at: ${path}`,
                    },
                ],
            };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
];
