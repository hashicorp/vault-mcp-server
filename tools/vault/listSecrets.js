import { z } from 'zod';
import { getSession } from '../../session.js';

export const toolListSecrets = [
    'list-secrets',
    'List the available secrets on a Vault Server',
    {
        mount: z.string().describe("The mount path (e.g., 'secrets')"),
        path: z.string().default('').describe("The full path to write the secret to, excluding the mount (e.g., 'foo/bar')"),
    },
    async ({ mount, path }, { sessionId /*, authInfo*/ }) => {
        let { vault } = getSession(sessionId);

        try {
            path = path.replace(/\/$/, '');

            const { data } = await vault.list(`${mount}/${path}`);
            return {
                content: [
                    {
                        type: 'text',
                        text: `Available sub paths: ${path}\n${JSON.stringify(data?.keys ?? [])}`,
                    },
                ],
            };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
];
