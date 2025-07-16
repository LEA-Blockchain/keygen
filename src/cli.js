#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const { generateKeyset, getAddressFromKeyset } = require('./generate');

/**
 * Parses command-line arguments for the keygen tool.
 * @returns {object} The parsed arguments.
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const command = args[0];
    const options = {
        command,
        force: args.includes('--force'),
        noOutfile: args.includes('--no-outfile'),
        outfile: null,
        infile: args[1] || null,
    };

    const outfileIndex = args.indexOf('--outfile');
    if (outfileIndex !== -1 && args[outfileIndex + 1]) {
        options.outfile = args[outfileIndex + 1];
    }

    if (command !== 'new' && command !== 'verify') {
        console.error("Error: Invalid command. Supported commands are 'new' and 'verify'.");
        process.exit(1);
    }

    return options;
}

async function handleNew(options) {
    const { keyset, address } = await generateKeyset();
    const keysetJson = JSON.stringify(keyset, null, 2);

    console.error(`Public Address: ${address}`);

    if (options.noOutfile) {
        console.log(keysetJson);
        console.error('Keyset generated to stdout.');
        return;
    }

    const outfilePath = options.outfile ? path.resolve(options.outfile) : path.resolve(`${address}.json`);

    try {
        const fileExists = await fs.access(outfilePath).then(() => true).catch(() => false);
        if (fileExists && !options.force) {
            console.error(
                `Error: Outfile already exists: ${outfilePath}. Use --force to overwrite.`
            );
            process.exit(1);
        }
    } catch (error) {
        console.error(`Error checking file: ${error.message}`);
        process.exit(1);
    }

    try {
        await fs.writeFile(outfilePath, keysetJson, { mode: 0o600 });
        console.error(`Keyset saved to: ${outfilePath}`);
    } catch (error) {
        console.error(`Error writing file: ${error.message}`);
        process.exit(1);
    }
}

async function handlePubkey(options) {
    if (!options.infile) {
        console.error('Error: Missing file path for verify command.');
        process.exit(1);
    }
    const infilePath = path.resolve(options.infile);
    try {
        const keysetJson = await fs.readFile(infilePath, 'utf8');
        const keyset = JSON.parse(keysetJson);
        const address = await getAddressFromKeyset(keyset);
        console.log(address);
    } catch (error) {
        console.error(`Error reading or processing keyset file: ${error.message}`);
        process.exit(1);
    }
}

/**
 * Main function to run the keygen tool.
 */
async function main() {
    const options = parseArgs();

    if (options.command === 'new') {
        await handleNew(options);
    } else if (options.command === 'verify') {
        await handlePubkey(options);
    }
}

main().catch((err) => {
    console.error(`An unexpected error occurred: ${err.message}`);
    process.exit(1);
});
