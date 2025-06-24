import { z } from 'zod';
import { getSession } from '../../session.js';

export const toolDeleteMount = [
    'delete-mount',
    'Delete a secret engine mount on Vault Server at a given path.',
    {
        path: z.string().describe("Path where the secret engine is mounted to, eg 'secrets'"),
    },
    async ({ path }, { sessionId /*, authInfo*/ }) => {
        try {
            let { vault } = getSession(sessionId);

            path = path.replace(/^\/|\/$/g, '');

            let payload = { mount_point: path };

            await vault.unmount(payload);

            return {
                content: [
                    {
                        type: 'text',
                        text: `Deleted mount : ${path}`,
                    },
                ],
            };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
];
