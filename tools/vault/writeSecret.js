import { z } from 'zod';
import { getSession } from '../../session.js';

export const toolWriteSecret = [
    'write-secret',
    'Write a secret on a Vault Server',
    {
        mount: z.string().describe("The mount path (e.g., 'secrets')"),
        path: z.string().describe("The full path to write the secret to, excluding the mount (e.g., 'foo/bar')"),
        key: z.string().describe('The key name for the secret'),
        value: z.string().describe('The value to store'),
    },
    async ({ mount, path, key, value }, { sessionId /*, authInfo*/ }) => {
        try {
            let { vault } = getSession(sessionId);

            let payload = { [key]: value };

            path = path.replace(/\/$/, '');

            let response = await vault.write(`${mount}/${path}`, payload);

            let text = `Secret ${key} created on the mount ${mount} at the path ${path}`;

            if (response) {
                let { data } = response;

                if (data) {
                    text += `, data:\n${JSON.stringify(data)}`;
                }
            }
            return {
                content: [
                    {
                        type: 'text',
                        text: text,
                    },
                ],
            };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
];
