import { z } from 'zod';

export const promptCreateSecret = [
    'Create a secret',
    {
        mount: z.string().describe("The mount path (e.g., 'secrets')"),
        path: z.string().describe("The full path to write the secret to, excluding the mount (e.g., 'foo/bar')"),
        key: z.string().describe('The key name for the secret'),
        value: z.string().describe('The value to store'),
    },
    async ({ mount, path, key, value }) => {
        return {
            messages: [
                {
                    role: 'user',
                    content: {
                        type: 'text',
                        text: `Firstly, make sure that the mount ${mount} exists using the 
list_mount tool. If it doesnt exist, create it with the create_mount 
tool using the kv type kv2 then store the secret ${value} in the path 
${path} using the key ${key}`,
                    },
                },
            ],
        };
    },
];
