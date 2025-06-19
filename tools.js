import { resourceMounts } from './resources/mounts.js';

import { toolCreateMount } from './tools/vault/createMount.js';
import { toolDeleteMount } from './tools/vault/deleteMount.js';
import { toolReadSecret } from './tools/vault/readSecret.js';
import { toolListSecrets } from './tools/vault/listSecrets.js';
import { toolListMounts } from './tools/vault/listMounts.js';
import { toolWriteSecret } from './tools/vault/writeSecret.js';

import { promptCreateSecret } from './prompts/createSecret.js';

export const vaultPrompts = [promptCreateSecret];
export const vaultResources = [resourceMounts];

export const vaultTools = [toolListMounts, toolCreateMount, toolDeleteMount, toolWriteSecret, toolReadSecret, toolListSecrets];
