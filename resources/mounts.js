import { getSession } from '../session.js';

export const resourceMounts = [
    'mounts',
    'mounts://',
    {
        title: 'Current vault mounts',
        description: 'A list of currently mounted secrets engines on vault',
    },
    async (uri, { sessionId /*, authInfo*/ }) => {
        try {
            let { vault } = getSession(sessionId);

            const { data } = await vault.mounts();

            return {
                contents: [
                    {
                        uri: uri.href,
                        text: `${JSON.stringify(data)}`,
                    },
                ],
            };
        } catch (err) {
            console.error(err);
            throw err;
        }
    },
];
