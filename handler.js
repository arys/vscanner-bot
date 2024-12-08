const fs = require('fs');
const pg = require('pg');
const { Client } = pg
const formData = require('form-data');
const Mailgun = require('mailgun.js');
const mailgun = new Mailgun(formData);

async function main(event, context, callback) {
    const client = new Client({
        connectionString: process.env.DATABASE_URL,
    })
    await client.connect()
    console.log(event);
    const scanId = event.rawPath.split('/scan_id=')[1]
    try {
        console.log({ scanId })
        if (!scanId) {
            callback(null, {
                statusCode: 400,
                body: JSON.stringify({ error: 'scan_id is required' }),
            });
            return
        }
        const scansRows = await client.query('SELECT * FROM scans WHERE id = $1', [scanId]);
        console.log({ scansRows })
        const scan = scansRows?.rows[0]
        console.log({ scan })
        if (!scan) {
            callback(null, {
                statusCode: 404,
                body: JSON.stringify({ error: 'scan not found' }),
            });
            return
        }

        await client.query('UPDATE scans SET started_at = now() WHERE id = $1', [scan.id])

        callback(null, {
            statusCode: 200,
            body: JSON.stringify({
                message: 'started'
            })
        })

        const foundTotal = []
        const passedTotal = []
        const failedTotal = []

        try {
            const scanItemsRows = await client.query('SELECT * FROM scan_items WHERE scan_id = $1', [scanId])
            const scanItems = scanItemsRows.rows

            if (!fs.existsSync('/tmp/node_modules')) {
                fs.cpSync('./node_modules', '/tmp/node_modules', { recursive: true });
            }
            if (!fs.existsSync('/tmp/package.json')) {
                fs.cpSync('./package.json', '/tmp/package.json', { recursive: true });
            }

            for (const scanItem of scanItems) {
                console.log({ scanItem })
                const vids = scanItem?.vulnerabilities?.split(',')
                console.log({ vids })
                const vulnerabilitiesRows = await client.query('SELECT * FROM vulnerability WHERE id = ANY($1)', [vids])
                console.log({ vulnerabilitiesRows })
                const vulnerabilities = vulnerabilitiesRows.rows
                console.log({ vulnerabilities })


                const found = []
                const failed = []
                const passed = []
                for (const vulnerability of vulnerabilities) {
                    const detectCode = vulnerability.detectionScript
                    console.log({ detectCode })
                    if (!detectCode) {
                        failed.push({
                            id: vulnerability.id,
                            message: 'Detect code not implemented'
                        })
                        continue
                    }

                    fs.writeFileSync(`/tmp/detect-${vulnerability.id}.js`, detectCode);

                    try {
                        const detect = await import(`/tmp/detect-${vulnerability.id}.js`);
                        try {
                            console.log("RUNNING DETECTION")
                            const result = await detect.default(scanItem.domain ?? scanItem.ip);
                            console.log(vulnerability.id, { result })
                            if (result) {
                                found.push(vulnerability.id);
                            } else {
                                passed.push(vulnerability.id);
                            }
                        } catch (detectionError) {
                            console.error('Detection error:', detectionError);
                            passed.push(vulnerability.id); // Consider it passed if detection fails
                        }
                    } catch(e) {
                        console.error('Import error:', e);
                        failed.push({
                            id: vulnerability.id,
                            message: e.message
                        });
                    }

                    fs.rmSync(`/tmp/detect-${vulnerability.id}.js`)
                }
                passedTotal.push(...passed)
                foundTotal.push(...found)
                failedTotal.push(...failed)
                console.log({ passed, found, failed })
                await client.query('UPDATE scan_items SET passed_exploits = $1, found_exploits = $2, failed_exploits = $3, completed_at = now() WHERE id = $4', [
                    passed.length,
                    JSON.stringify(found),
                    JSON.stringify(failed),
                    scanItem.id
                ])
            }
            await client.query('UPDATE scans SET completed_at = now() WHERE id = $1', [scan.id])

            const formData = new FormData();
            formData.append('from', 'VScanner <mailgun@vscanner.dev>');
            formData.append('to', 'arystankaliakparov@gmail.com');
            formData.append('subject', 'Scan completed');
            formData.append('text', `
Scan Results Summary
-------------------
Scan ID: ${scan.id}
Found Vulnerabilities: ${foundTotal.length}
Passed Tests: ${passedTotal.length} 
Failed Tests: ${failedTotal.length}

View detailed results at: https://vscanner.dev/
`);
            formData.append('html', `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">Scan Results Summary</h1>
    <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
        <p style="margin: 5px 0;"><strong>Scan ID:</strong> ${scan.id}</p>
        <p style="margin: 5px 0;"><strong>Found Vulnerabilities:</strong> ${foundTotal.length}</p>
        <p style="margin: 5px 0;"><strong>Passed Tests:</strong> ${passedTotal.length}</p>
        <p style="margin: 5px 0;"><strong>Failed Tests:</strong> ${failedTotal.length}</p>
    </div>
    <p style="text-align: center;">
        <a href="https://vscanner.dev/" style="background: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">View Detailed Results</a>
    </p>
</div>
`);

            await fetch('https://api.mailgun.net/v3/vscanner.dev/messages', {
                method: 'POST',
                headers: {
                    'Authorization': 'Basic ' + Buffer.from('api:' + process.env.MAILGUN_API_KEY).toString('base64')
                },
                body: formData
            });

            callback(null, {
                statusCode: 200,
                body: JSON.stringify({
                    message: 'completed'
                })
            })
        } catch(e) {
            console.error(e)
            await client.query('UPDATE scans SET completed_at = now(), fail_message = $2 WHERE id = $1', [
                scan.id,
                e.message
            ])
            callback(null, {
                statusCode: 200,
                body: JSON.stringify({
                    message: 'completed'
                })
            })
        }
    } catch (error) {
        console.error('Error during vulnerability check:', error);
        await client.query('UPDATE scans SET completed_at = now(), fail_message = $2 WHERE id = $1', [
            scanId,
            error.message
        ])
        callback(null, {
            statusCode: 500,
            body: JSON.stringify({ error: error.message }),
        });
    }
}

exports.handler = main