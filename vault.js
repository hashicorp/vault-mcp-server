import { default as NodeVault } from 'node-vault';

export class Vault {
    #instance; // NodeVault Instance
    #namespace; // Namespace which will be prepended to paths

    constructor(endpoint, token, namespace = null, mount = null) {
        this.#namespace = namespace; // Unused for now
        this.#instance = NodeVault({
            endpoint,
            token,
        });
    }

    #constructPath(path) {
        let parts = [];
        parts = [...parts, ...path.split('/')];
        return parts.join('/');
    }

    mounts = async () => this.#instance.mounts();

    mount = async (data) => this.#instance.mount(data);

    unmount = async (data) => this.#instance.unmount(data);

    list = async (path) => {
        let parts = this.#constructPath(path).split('/');
        let mount = parts.shift();

        let mounts = await this.#instance.mounts();

        let secretsEngine = mounts[mount + '/'];

        if (secretsEngine?.options?.version === '2') {
            parts = [mount, 'metadata', ...parts];
        } else {
            parts = [mount, ...parts];
        }

        return this.#instance.list(this.#constructPath(parts.join('/')));
    };

    write = async (path, data) => {
        let parts = this.#constructPath(path).split('/');
        let mount = parts.shift();

        let mounts = await this.#instance.mounts();

        let secretsEngine = mounts[`${mount}/`];

        if (secretsEngine?.options?.version === '2') {
            parts = [mount, 'data', ...parts];
            data = { data };
        } else {
            parts = [mount, ...parts];
        }

        return this.#instance.write(parts.join('/'), data);
    };

    read = async (path) => {
        let parts = this.#constructPath(path).split('/');
        let mount = parts.shift();

        let mounts = await this.#instance.mounts();

        let secretsEngine = mounts[mount + '/'];

        if (secretsEngine?.options?.version === '2') {
            parts = [mount, 'data', ...parts];
        } else {
            parts = [mount, ...parts];
        }

        return this.#instance.read(parts.join('/'));
    };
}
