import { z } from 'zod';
import { getSession } from '../../session.js';

export const toolReadSecret = [
    'read-secret',
    'Read a secret from a Vault Server using the given mount and path',
    {
        mount: z.string().describe("The mount path (e.g., 'secrets')"),
        path: z.string().describe("The full path to write the secret to, excluding the mount (e.g., 'foo/bar')"),
    },
    async ({ mount, path }, { sessionId /*, authInfo*/ }) => {
        try {
            let { vault } = getSession(sessionId);

            path = path.replace(/\/$/, '');

            const { data } = await vault.read(`${mount}/${path}`);

            return {
                content: [
                    {
                        type: 'text',
                        text: `Secret read at ${mount}/${path}:\n${JSON.stringify(data)}`,
                    },
                ],
            };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
];
