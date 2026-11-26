// Test-only producer for the real Python broker's Unix protocol. No engine access.
import net from 'node:net';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
const [helper, socket, request] = process.argv.slice(2);
const {requestUvm} = await import(pathToFileURL(helper));
const result = await requestUvm(JSON.parse(fs.readFileSync(request, 'utf8')),
                                () => net.createConnection(socket));
process.stdout.write(JSON.stringify(result) + '\n');
