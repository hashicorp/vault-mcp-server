import { getSession } from '../../session.js';

export const toolListMounts = [
    'list-mounts',
    'List the available mounted secrets engines on a Vault Server',
    {},
    async ({}, { sessionId /*, authInfo*/ }) => {
        let { vault } = getSession(sessionId);

        try {
            const { data } = await vault.mounts();
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify(data),
                    },
                ],
            };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
];
