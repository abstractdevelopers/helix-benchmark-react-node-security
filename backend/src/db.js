import { JSONFilePreset } from 'lowdb/node';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const db = await JSONFilePreset(join(__dirname, '../data.json'), { users: [], notes: [] });
